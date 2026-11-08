"""Schema intelligence from AUTHORIZED SQL DDL exports. Technology is never inferred from a domain name."""
import re
from sqlalchemy.orm import Session
from app.models import DatabaseSchema, DatabaseTable
from app.services import normalize

TECH_HINTS = [("mysql", r"ENGINE\s*=\s*InnoDB|AUTO_INCREMENT"), ("postgresql", r"\bSERIAL\b|\bJSONB\b|::\w+|\bBIGSERIAL\b"),
              ("sqlite", r"\bAUTOINCREMENT\b"), ("sqlserver", r"\bNVARCHAR\b|\bIDENTITY\s*\(")]
SENS = [("restricted", r"password|passwd|secret|token|api_?key|private_?key|credential|ssn|card_?number|cvv"),
        ("confidential", r"email|phone|address|birth|dob|salary|iban|passport|full_?name|first_?name|last_?name")]
RANK = ["public", "internal", "confidential", "restricted"]
OWNER = re.compile(r"^(user_id|owner_id|account_id|tenant_id|org_id|organization_id|customer_id|created_by)$", re.I)
CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"\[]?([\w.]+)[`\"\]]?\s*\((.*?)\)\s*(?:ENGINE[^;]*)?;", re.I | re.S)


def _split(body: str) -> list[str]:
    parts, depth, cur = [], 0, ""
    for ch in body:
        depth += ch == "("; depth -= ch == ")"
        if ch == "," and depth == 0:
            parts.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def classify_column(name: str) -> str:
    for level, rx in SENS:
        if re.search(rx, name, re.I):
            return level
    return "internal"


def parse_ddl(sql: str, declared_technology: str | None = None) -> dict:
    tables, tech, conf = [], declared_technology, "high" if declared_technology else "low"
    if not tech:
        for t, rx in TECH_HINTS:
            if re.search(rx, sql, re.I):
                tech, conf = t, "low"; break
    for name, body in CREATE.findall(sql):
        cols, pk, fks = [], [], []
        for part in _split(body):
            up = part.upper()
            m = re.match(r"(?:CONSTRAINT\s+\w+\s+)?PRIMARY\s+KEY\s*\(([^)]+)\)", part, re.I)
            if m:
                pk += [c.strip(" `\"[]") for c in m.group(1).split(",")]; continue
            m = re.match(r"(?:CONSTRAINT\s+\w+\s+)?FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+[`\"]?([\w.]+)[`\"]?\s*\(([^)]+)\)", part, re.I)
            if m:
                fks.append({"columns": [c.strip(" `\"") for c in m.group(1).split(",")], "ref_table": m.group(2),
                            "ref_columns": [c.strip(" `\"") for c in m.group(3).split(",")]}); continue
            if up.startswith(("UNIQUE", "KEY", "INDEX", "CHECK", "CONSTRAINT")):
                continue
            m = re.match(r"[`\"\[]?(\w+)[`\"\]]?\s+([A-Za-z]+(?:\([^)]*\))?)(.*)", part, re.S)
            if not m:
                continue
            cname, ctype, rest = m.group(1), m.group(2), m.group(3)
            if re.search(r"PRIMARY\s+KEY", rest, re.I):
                pk.append(cname)
            r = re.search(r"REFERENCES\s+[`\"]?([\w.]+)[`\"]?\s*\(([^)]+)\)", rest, re.I)
            if r:
                fks.append({"columns": [cname], "ref_table": r.group(1), "ref_columns": [c.strip(" `\"") for c in r.group(2).split(",")]})
            cols.append({"name": cname, "type": ctype, "nullable": not re.search(r"NOT\s+NULL|PRIMARY\s+KEY", rest, re.I),
                         "sensitivity": classify_column(cname)})
        top = max((c["sensitivity"] for c in cols), key=RANK.index, default="internal")
        tables.append({"name": name, "columns": cols, "primary_key": pk, "foreign_keys": fks,
                       "ownership_columns": [c["name"] for c in cols if OWNER.match(c["name"])], "sensitivity": top})
    return {"technology": tech or "unknown", "technology_confidence": conf, "tables": tables}


def persist(db: Session, assessment_id: str, name: str, sql: str, technology: str | None) -> tuple[DatabaseSchema, dict]:
    res = parse_ddl(sql, technology)
    ob = normalize.record(db, assessment_id=assessment_id, asset_id=None, category="database_schema_analysis",
                          source="schema_export", reference=f"schema:{name}", confidence="high",
                          description=f"Parsed {len(res['tables'])} tables from schema export '{name}' (technology={res['technology']})",
                          payload={"tables": [t["name"] for t in res["tables"]], "technology": res["technology"]})
    schema = DatabaseSchema(assessment_id=assessment_id, evidence_id=ob.evidence_id, name=name, technology=res["technology"],
                            technology_confidence=res["technology_confidence"], source="schema_export")
    db.add(schema); db.flush()
    for t in res["tables"]:
        db.add(DatabaseTable(schema_id=schema.id, **t))
    return schema, res
