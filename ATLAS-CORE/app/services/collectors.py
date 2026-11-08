"""External intelligence collectors. Every host is scope-checked before it is touched.
Collected assets are recorded as discovered; only scope rules can authorize them."""
import ipaddress, re, socket, ssl, time
from dataclasses import dataclass
from datetime import timezone
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlparse
import httpx
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.models import ApiEndpoint
from app.services import netguard, normalize, scope
from app.services.audit import audit

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-content-type-options",
                    "referrer-policy", "permissions-policy"]
SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs"]
ALL_COLLECTORS = ["rdap", "dns", "ct", "http", "tls", "api_docs"]


# ---------- default (real) transports ----------
def _dns(host: str) -> dict:
    out: dict = {}
    try:
        import dns.resolver
        for rt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            try:
                out[rt] = [r.to_text() for r in dns.resolver.resolve(host, rt, lifetime=5)]
            except Exception:
                pass
        return out
    except ImportError:
        pass
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None):
            out.setdefault("AAAA" if fam == socket.AF_INET6 else "A", []).append(sa[0])
    except socket.gaierror:
        pass
    return out


def _http(url: str) -> dict:
    s = get_settings()
    with httpx.Client(follow_redirects=False, timeout=10, headers={"User-Agent": s.user_agent}) as c:
        with c.stream("GET", url) as r:
            body, n = [], 0
            for chunk in r.iter_bytes():
                body.append(chunk); n += len(chunk)
                if n > 200_000:
                    break
            return {"url": url, "status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": b"".join(body).decode("utf-8", "replace")}


def _tls(host: str, port: int = 443) -> dict:
    from cryptography import x509
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock, ctx.wrap_socket(sock, server_hostname=host) as ss:
        der, proto, cipher = ss.getpeercert(binary_form=True), ss.version(), ss.cipher()[0]
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:
        san = []
    verified, err = True, None
    try:
        with socket.create_connection((host, port), timeout=10) as sock, \
                ssl.create_default_context().wrap_socket(sock, server_hostname=host):
            pass
    except ssl.SSLCertVerificationError as e:
        verified, err = False, str(e)
    return {"protocol": proto, "cipher": cipher, "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(), "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(), "san": list(san), "verified": verified,
            "verify_error": err}


def _resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def _ct(domain: str) -> list[str]:
    r = httpx.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
    r.raise_for_status()
    names = set()
    for row in r.json():
        for n in row.get("name_value", "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
    return sorted(names)[:500]


def _rdap(domain: str) -> dict:
    r = httpx.get(f"https://rdap.org/domain/{domain}", timeout=15, follow_redirects=True)
    r.raise_for_status()
    return r.json()


@dataclass
class Transports:
    dns: Callable = _dns
    http: Callable = _http
    tls: Callable = _tls
    ct: Callable = _ct
    rdap: Callable = _rdap
    resolve: Callable = _resolve


_transports = Transports()


def get_transports() -> Transports:
    return _transports


# ---------- parsing helpers ----------
class _Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title, self._in_title, self.scripts, self.links, self.generator = "", False, [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "script" and a.get("src"):
            self.scripts.append({"src": a["src"], "sri": bool(a.get("integrity"))})
        elif tag == "link" and a.get("href"):
            self.links.append({"href": a["href"], "sri": bool(a.get("integrity"))})
        elif tag == "meta" and (a.get("name") or "").lower() == "generator":
            self.generator = a.get("content")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()


FINGERPRINTS = [
    ("header", "server", r"^(nginx|apache|microsoft-iis|cloudflare|gunicorn|caddy|openresty|litespeed|envoy)(?:/([\d.]+))?", "web_server", "high"),
    ("header", "x-powered-by", r"^(php|express|asp\.net|next\.js)(?:/([\d.]+))?", "framework", "high"),
    ("generator", None, r"^([A-Za-z0-9 .\-]+?)\s+([\d.]+)$", "cms", "medium"),
    ("script", None, r"(jquery)[-.]?(\d[\d.]*)?(?:\.min)?\.js", "javascript_library", "medium"),
    ("script", None, r"(bootstrap)[-.@/]?(\d[\d.]*)?", "javascript_library", "low"),
    ("script", None, r"(wp-content|wp-includes)", "cms", "medium"),
    ("cookie", None, r"(PHPSESSID|JSESSIONID|laravel_session|connect\.sid|csrftoken|ASP\.NET_SessionId)", "framework_hint", "low"),
]


def fingerprint(headers: dict, page: _Page) -> list[dict]:
    found = []
    for kind, key, rx, cat, conf in FINGERPRINTS:
        subjects = []
        if kind == "header" and headers.get(key):
            subjects = [headers[key]]
        elif kind == "generator" and page.generator:
            subjects = [page.generator]
        elif kind == "script":
            subjects = [s["src"] for s in page.scripts]
        elif kind == "cookie" and headers.get("set-cookie"):
            subjects = [headers["set-cookie"]]
        for s in subjects:
            m = re.search(rx, s, re.I)
            if m:
                name = m.group(1)
                ver = m.group(2) if m.lastindex and m.lastindex >= 2 else None
                found.append({"name": name, "version": ver, "category": cat, "confidence": conf})
    uniq = {(f["name"].lower(), f["version"]): f for f in found}
    return list(uniq.values())


# ---------- orchestration ----------
def _link(rel, a, b):
    return {"relation": rel, "from": list(a), "to": list(b)}


def collect_host(db: Session, assessment_id: str, host: str, collectors: list[str], ctx, pause: float) -> list[str]:
    tr = ctx.transports
    asset_type = "domain" if host.count(".") <= 1 else "subdomain"
    asset = normalize.ensure_asset(db, assessment_id, asset_type, host, "collector")
    done = []
    rec = lambda **kw: normalize.record(db, assessment_id=assessment_id, **kw)  # noqa: E731

    if "rdap" in collectors:
        d = tr.rdap(host)
        events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
        rec(asset_id=asset.id, category="domain_registration", source="rdap",
            reference=f"https://rdap.org/domain/{host}", confidence="high",
            description=f"RDAP record for {host}: status={d.get('status')}, events={events}",
            payload={"ldhName": d.get("ldhName"), "status": d.get("status"), "events": events})
        done.append("rdap")
    if "dns" in collectors:
        recs = tr.dns(host)
        links = []
        for rt, vals in recs.items():
            for v in vals:
                if rt in ("A", "AAAA"):
                    ip = normalize.ensure_asset(db, assessment_id, "ip", v, "dns")
                    links.append(_link("resolves_to", (asset_type, host), ("ip", ip.value)))
                elif rt == "CNAME":
                    t = v.rstrip(".").lower()
                    normalize.ensure_asset(db, assessment_id, "subdomain", t, "dns")
                    links.append(_link("aliases", (asset_type, host), ("subdomain", t)))
        rec(asset_id=asset.id, category="dns_records", source="dns", reference=f"dns://{host}", confidence="high",
            description=f"DNS records for {host}: " + "; ".join(f"{k}={v}" for k, v in recs.items()),
            payload={"records": recs, "links": links})
        done.append("dns")
    if "ct" in collectors:
        names = tr.ct(host)
        for n in names:
            normalize.ensure_asset(db, assessment_id, "domain" if n == host else "subdomain", n, "certificate_transparency")
        rec(asset_id=asset.id, category="certificate_transparency", source="crt.sh",
            reference=f"https://crt.sh/?q=%25.{host}", confidence="medium",
            description=f"{len(names)} names seen in certificate transparency logs for {host}",
            payload={"names": names})
        done.append("ct")
    if "tls" in collectors:
        time.sleep(pause)
        ok, _, _ = netguard.authorize_url(db, assessment_id, f"https://{host}/", ctx)
        if not ok:
            collectors = [c for c in collectors if c != "tls"]
    if "tls" in collectors:
        t = tr.tls(host)
        rec(asset_id=asset.id, category="tls_configuration", source="tls_probe", reference=f"tls://{host}:443",
            confidence="high",
            description=(f"{host} negotiated {t.get('protocol')} / {t.get('cipher')}; issuer={t.get('issuer')}; "
                         f"expires={t.get('not_after')}; chain verified={t.get('verified')}"),
            payload=t)
        done.append("tls")
    if "http" in collectors:
        time.sleep(pause)
        base = f"https://{host}/"
        r = netguard.safe_fetch(db, assessment_id, base, ctx)
        if r.get("blocked"):
            r = None
    if "http" in collectors and r is not None:
        h, page = r["headers"], _Page()
        page.feed(r.get("body", ""))
        keep = {k: h[k] for k in ("server", "content-type", "location", "x-powered-by", "via", "cache-control") if k in h}
        if "location" in keep:  # Location may carry tokens in its query string: never persist them
            keep["location"] = netguard.safe_url(keep["location"])
        rec(asset_id=asset.id, category="http_response_metadata", source="http_probe", reference=f"GET {base}",
            confidence="high", description=f"GET {base} returned {r['status']}; headers={keep}; title={page.title!r}",
            payload={"status": r["status"], "headers": keep, "title": page.title, "redirect_chain": r["chain"],
                     **({"redirect_blocked": r["redirect_blocked"]} if r.get("redirect_blocked") else {})})
        missing = [s for s in SECURITY_HEADERS if s not in h]
        rec(asset_id=asset.id, category="http_security_headers", source="http_probe", reference=f"GET {base}",
            confidence="high", description=f"Response from {base} did not include: {', '.join(missing) or 'none missing'}",
            payload={"missing": missing, "present": [s for s in SECURITY_HEADERS if s in h]})
        res = [{"url": urljoin(base, s["src"]), "type": "script", "sri": s["sri"]} for s in page.scripts] + \
              [{"url": urljoin(base, l["href"]), "type": "link", "sri": l["sri"]} for l in page.links]
        third, links = [], []
        for x in res:
            hh = scope.normalize_host(x["url"])
            if hh and hh != host and not hh.endswith("." + host):
                third.append({"host": hh, "type": x["type"], "sri": x["sri"], "url": x["url"]})
                normalize.ensure_asset(db, assessment_id, "third_party", hh, "browser_resources")
                links.append(_link("references", (asset_type, host), ("third_party", hh)))
        rec(asset_id=asset.id, category="browser_resources", source="http_probe", reference=f"GET {base}",
            confidence="high", description=f"{base} loads {len(res)} resources, {len(third)} from third-party hosts",
            payload={"resources": res, "third_party": third, "links": links})
        fp_obs = None
        for f in fingerprint(h, page):
            fp_obs = fp_obs or rec(asset_id=asset.id, category="technology_fingerprint", source="http_probe",
                                   reference=f"GET {base}", confidence="medium",
                                   description=f"Fingerprints observed at {base}",
                                   payload={"fingerprints": fingerprint(h, page)})
            normalize.add_technology(db, assessment_id=assessment_id, asset_id=asset.id, evidence_id=fp_obs.evidence_id,
                                     name=f["name"], version=f["version"], category=f["category"],
                                     confidence=f["confidence"])
        done.append("http")
    if "api_docs" in collectors:
        for p in SPEC_PATHS:
            time.sleep(pause)
            url = f"https://{host}{p}"
            try:
                r = netguard.safe_fetch(db, assessment_id, url, ctx)
            except Exception:
                continue
            if r.get("blocked") or r["status"] != 200:
                continue
            try:
                import json
                spec = json.loads(r["body"])
            except ValueError:
                continue
            paths = spec.get("paths") if isinstance(spec, dict) else None
            if not paths:
                continue
            ob = rec(asset_id=asset.id, category="api_documentation", source="http_probe", reference=f"GET {url}",
                     confidence="high", description=f"Public API description at {url} lists {len(paths)} paths",
                     payload={"paths": {k: sorted(v.keys()) for k, v in paths.items() if isinstance(v, dict)}})
            for path, ops in paths.items():
                for m in (ops or {}):
                    if m.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                        db.add(ApiEndpoint(assessment_id=assessment_id, asset_id=asset.id, evidence_id=ob.evidence_id,
                                           method=m.upper(), path=path, documented=True,
                                           auth_scheme=("declared" if ops[m].get("security") else None),
                                           description=ops[m].get("summary")))
            done.append("api_docs")
            break
    return done


def run_collection(db: Session, assessment_id: str, hosts: list[str], collectors: list[str], actor_id=None):
    """Each host is scope-checked first; every host runs inside a SAVEPOINT so a failure leaves no partial data."""
    s = get_settings()
    ctx = netguard.ScopeContext(actor_id, "collect", get_transports())
    summary = {"collected": [], "skipped": [], "errors": []}
    for host in hosts:
        host = scope.normalize_host(host)
        ok, why = scope.check_access(db, assessment_id, host)
        ctx.log(0, host, ok, why)
        if not ok:
            summary["skipped"].append({"host": host, "reason": why})
            ctx.flush(db, assessment_id)
            continue
        try:
            with db.begin_nested():
                done = collect_host(db, assessment_id, host, collectors, ctx, s.collector_min_interval_seconds)
            summary["collected"].append({"host": host, "collectors": done})
        except Exception as e:  # collector failures must not abort the run or leave partial rows
            summary["errors"].append({"host": host, "error": f"{type(e).__name__}: {e}"})
        ctx.flush(db, assessment_id)
        audit(db, actor_id=actor_id, action="collect", resource_type="assessment", resource_id=assessment_id,
              assessment_id=assessment_id, details={"host": host, "collectors": collectors})
    return summary
