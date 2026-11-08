"""Static analysis of AUTHORIZED source code. Never executes the code."""
import hashlib, re
from collections import Counter
from sqlalchemy.orm import Session
from app.models import ApplicationRoute
from app.services import normalize

LANG = {".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby",
        ".php": "PHP", ".cs": "C#", ".kt": "Kotlin"}
FRAMEWORK_HINTS = [("FastAPI", r"from fastapi|import fastapi"), ("Flask", r"from flask|import flask"),
                   ("Django", r"from django|import django"), ("Express", r"require\(['\"]express['\"]\)|from ['\"]express['\"]"),
                   ("Spring", r"org\.springframework"), ("Laravel", r"Illuminate\\"), ("Rails", r"Rails\.application")]
ROUTE_EXT = {"FastAPI/Flask": (".py",), "Flask": (".py",), "Django": (".py",), "Express": (".js", ".ts", ".mjs", ".cjs"), "Spring": (".java", ".kt")}
ROUTE_PATTERNS = [
    ("FastAPI/Flask", re.compile(r"@\w+\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)", re.I)),
    ("Flask", re.compile(r"@\w+\.route\(\s*['\"]([^'\"]+)['\"](?:.*?methods\s*=\s*\[([^\]]+)\])?", re.I)),
    ("Express", re.compile(r"\b(?:app|router)\.(get|post|put|delete|patch)\(\s*['\"`]([^'\"`]+)", re.I)),
    ("Django", re.compile(r"\b(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]")),
    ("Spring", re.compile(r"@(Get|Post|Put|Delete|Patch)Mapping\(\s*(?:value\s*=\s*)?\"([^\"]+)\"")),
]
AUTH_IN_ROUTE = re.compile(r"login_required|Depends\(\s*(?:get_current|require|current)\w*|@authenticated|"
                           r"requireAuth|authMiddleware|passport\.authenticate|@PreAuthorize|IsAuthenticated|verifyToken", re.I)
AUTH_MECH = {"JWT": r"\bjwt\b|jsonwebtoken", "OAuth2": r"oauth", "Session cookies": r"session\b|express-session|SessionMiddleware",
             "Passport": r"passport", "Basic auth": r"basic[_ ]?auth|HTTPBasic", "API keys": r"api[_-]?key"}
MIDDLEWARE = re.compile(r"add_middleware\(\s*(\w+)|app\.use\(\s*([\w.]+)|MIDDLEWARE\s*=\s*\[|@app\.before_request", re.I)
INTEGRATIONS = {"Stripe": r"\bstripe\b", "AWS": r"\bboto3\b|aws-sdk", "Twilio": r"\btwilio\b", "SendGrid": r"sendgrid",
                "Redis": r"\bredis\b", "Kafka": r"\bkafka\b", "S3": r"\bs3\b", "Firebase": r"firebase"}
ENV_VARS = re.compile(r"os\.environ(?:\.get)?\(?\[?['\"](\w+)|os\.getenv\(['\"](\w+)|process\.env\.(\w+)")
EXT_URL = re.compile(r"https?://([a-z0-9.\-]+\.[a-z]{2,})", re.I)


def _context(lines: list[str], i: int) -> str:
    """Decorators stacked above the route + lines up to and including the handler signature."""
    lo = i
    while lo > 0 and lines[lo - 1].strip().startswith("@"):
        lo -= 1
    hi = i
    while hi < len(lines) - 1 and hi < i + 4 and not re.search(r"\b(def|function|class)\b|=>", lines[hi]):
        hi += 1
    return "\n".join(lines[lo: hi + 1])


def analyze_files(files: dict[str, str]) -> dict:
    langs, frameworks, routes, auth, mw, integ, env, hosts = Counter(), set(), [], set(), set(), set(), set(), set()
    for path, text in files.items():
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if ext in LANG:
            langs[LANG[ext]] += 1
        for name, rx in FRAMEWORK_HINTS:
            if re.search(rx, text):
                frameworks.add(name)
        for name, rx in AUTH_MECH.items():
            if re.search(rx, text, re.I):
                auth.add(name)
        for name, rx in INTEGRATIONS.items():
            if re.search(rx, text, re.I):
                integ.add(name)
        for m in MIDDLEWARE.finditer(text):
            mw.add(next((g for g in m.groups() if g), "middleware_stack"))
        for m in ENV_VARS.finditer(text):
            env.add(next(g for g in m.groups() if g))
        for m in EXT_URL.finditer(text):
            hosts.add(m.group(1).lower())
        lines = text.splitlines()
        for fw, rx in ROUTE_PATTERNS:
            if ext not in ROUTE_EXT[fw]:
                continue  # e.g. a Python `@app.get(...)` decorator must not also be read as Express
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                if fw == "Flask":
                    methods = re.findall(r"[A-Za-z]+", m.group(2) or "GET")
                    pairs = [(x.upper(), m.group(1)) for x in methods]
                elif fw == "Django":
                    pairs = [("ANY", m.group(1))]
                else:
                    pairs = [(m.group(1).upper(), m.group(2))]
                ctx = _context(lines, line - 1)
                for method, p in pairs:
                    routes.append({"framework": fw, "method": method, "path": p, "file": path, "line": line,
                                   "auth_required": True if AUTH_IN_ROUTE.search(ctx) else None})
    seen, uniq = set(), []
    for r in routes:  # same route found by two patterns (e.g. Flask + FastAPI regexes) is stored once
        k = (r["method"], r["path"], r["file"], r["line"])
        if k not in seen:
            seen.add(k); uniq.append(r)
    routes = uniq
    return {"languages": dict(langs), "frameworks": sorted(frameworks), "routes": routes,
            "authentication_mechanisms": sorted(auth), "middleware": sorted(mw), "external_integrations": sorted(integ),
            "external_hosts": sorted(hosts), "configuration_variables": sorted(env)}


def persist(db: Session, assessment_id: str, files: dict[str, str], label: str) -> dict:
    res = analyze_files(files)
    digest = hashlib.sha256("".join(sorted(f"{k}:{hashlib.sha256(v.encode()).hexdigest()}" for k, v in files.items())).encode()).hexdigest()
    ob = normalize.record(db, assessment_id=assessment_id, asset_id=None, category="application_source_analysis",
                          source="source_code", reference=f"source:{label}#{digest[:12]}", confidence="high",
                          description=(f"Static analysis of {len(files)} files: languages={res['languages']}, "
                                       f"frameworks={res['frameworks']}, {len(res['routes'])} routes, "
                                       f"auth={res['authentication_mechanisms']}"),
                          payload={**{k: v for k, v in res.items() if k != "routes"}, "route_count": len(res["routes"]),
                                   "links": [{"relation": "integrates_with", "from": ["application_server", label],
                                              "to": ["third_party", h]} for h in res["external_hosts"]]})
    asset = normalize.ensure_asset(db, assessment_id, "application_server", label, "source_code")
    ob.asset_id = asset.id
    for h in res["external_hosts"]:
        normalize.ensure_asset(db, assessment_id, "third_party", h, "source_code")
    for name in list(res["languages"]) + res["frameworks"]:
        normalize.add_technology(db, assessment_id=assessment_id, asset_id=asset.id, evidence_id=ob.evidence_id, name=name,
                                 version=None, category="language" if name in res["languages"] else "framework",
                                 confidence="high")
    for r in res["routes"]:
        db.add(ApplicationRoute(assessment_id=assessment_id, evidence_id=ob.evidence_id, method=r["method"], path=r["path"],
                                framework=r["framework"], source_file=r["file"], line=r["line"],
                                auth_required=r["auth_required"]))
    return res
