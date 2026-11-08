"""Network guard: every outbound request to a target goes through here.

 * strict URL parsing with the SAME parser the HTTP client uses (no parser differentials)
 * scope + authorization checked BEFORE each request, including every redirect hop
 * hosts resolving to non-public addresses are refused unless an explicit ip/cidr include rule covers them
 * every decision is recorded (ScopeContext.flush -> audit_logs, never containing query strings)
"""
import ipaddress, re
from dataclasses import dataclass, field
import httpx
from urllib.parse import urljoin
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.errors import ScopeViolation
from app.services import scope
from app.services.audit import audit

REDIRECT = {301, 302, 303, 307, 308}
_BAD = re.compile(r"[\s\\\x00-\x1f\x7f]")


safe_url = scope.redact_url


def strict_parse(url: str) -> tuple[str, str, int]:
    if not isinstance(url, str) or len(url) > 2048 or _BAD.search(url):
        raise ValueError("malformed URL")
    u = httpx.URL(url)
    if u.scheme not in ("http", "https"):
        raise ValueError("scheme not permitted")
    if u.userinfo:
        raise ValueError("credentials in URL not permitted")
    if not u.host:
        raise ValueError("missing host")
    port = u.port or (443 if u.scheme == "https" else 80)
    allowed = {int(p) for p in get_settings().allowed_ports.split(",") if p.strip()}
    if port not in allowed:
        raise ValueError(f"port {port} not permitted")
    return str(u), u.host.lower().rstrip("."), port


@dataclass
class ScopeContext:
    actor_id: str | None
    action: str
    transports: object
    decisions: list = field(default_factory=list)

    def log(self, hop: int, url: str, allowed: bool, reason: str) -> None:
        self.decisions.append({"hop": hop, "url": safe_url(url), "allowed": allowed, "reason": reason})

    def flush(self, db: Session, assessment_id: str) -> None:
        for d in self.decisions:
            audit(db, actor_id=self.actor_id, action="scope_decision", resource_type="scope", assessment_id=assessment_id,
                  outcome="allowed" if d["allowed"] else "denied", details={**d, "operation": self.action})
        self.decisions.clear()


def _address_guard(db: Session, aid: str, host: str, tr) -> tuple[bool, str]:
    try:
        ips = [host] if ipaddress.ip_address(host) else []
    except ValueError:
        ips = tr.resolve(host) or []
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_global and scope.classify(db, aid, str(addr))[0] != "authorized":
            return False, f"{host} resolves to non-public address {addr}; an explicit ip/cidr include rule is required"
    return True, "ok"


def authorize_url(db: Session, aid: str, url: str, ctx: ScopeContext, hop: int = 0) -> tuple[bool, str, str | None]:
    try:
        norm, host, _ = strict_parse(url)
    except (ValueError, httpx.InvalidURL) as e:
        ctx.log(hop, url, False, f"invalid URL: {e}")
        return False, f"invalid URL: {e}", None
    ok, why = scope.check_access(db, aid, norm)
    if ok:
        ok, why = _address_guard(db, aid, host, ctx.transports)
    ctx.log(hop, norm, ok, why)
    return ok, why, norm


def require_url(db: Session, aid: str, url: str, ctx: ScopeContext) -> str:
    ok, why, norm = authorize_url(db, aid, url, ctx)
    if not ok:
        ctx.flush(db, aid)
        db.commit()
        raise ScopeViolation(why, {"url": safe_url(url), "action": ctx.action})
    return norm


def safe_fetch(db: Session, aid: str, url: str, ctx: ScopeContext, *, max_redirects: int | None = None) -> dict:
    """GET with per-hop authorization. A denied FIRST hop returns {'blocked': True}; a denied redirect hop
    returns the redirecting response annotated with 'redirect_blocked'. Nothing is requested before approval."""
    limit = get_settings().max_redirects if max_redirects is None else max_redirects
    cur, chain, last = url, [], None
    for hop in range(limit + 1):
        ok, why, norm = authorize_url(db, aid, cur, ctx, hop)
        if not ok:
            if last is None:
                return {"blocked": True, "reason": why, "chain": chain}
            return {**last, "redirect_blocked": {"to": safe_url(cur), "reason": why}}
        r = ctx.transports.http(norm)
        chain = chain + [{"url": safe_url(norm), "status": r["status"]}]
        last = {**r, "blocked": False, "chain": chain, "final_url": safe_url(norm)}
        loc = (r.get("headers") or {}).get("location")
        if r["status"] in REDIRECT and loc:
            nxt = urljoin(norm, loc)
            if hop < limit:
                cur = nxt
                continue
            last["redirect"] = {"to": safe_url(nxt), "followed": False, "scope_state": scope.classify(db, aid, nxt)[0]}
        return last
    return last
