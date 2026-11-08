"""Regenerate openapi.json + data-models.md into ATLAS-CORE/contracts and ../ATLAS-SHARED/contracts."""
import json, pathlib, shutil
from app.db.session import Base
import app.models  # noqa: F401
from app.main import app

root = pathlib.Path(__file__).resolve().parents[1]
shared = root.parent / "ATLAS-SHARED"
spec = json.dumps(app.openapi(), indent=2)

md = ["# ATLAS Data Models", "", "Generated from the SQLAlchemy models. IDs are UUID strings. Timestamps are ISO-8601 UTC.", ""]
for t in Base.metadata.sorted_tables:
    md += [f"## {t.name}", "", "| column | type | nullable | notes |", "|---|---|---|---|"]
    for c in t.columns:
        if c.name in ("password_hash", "credentials_encrypted"):
            note = "never exposed by API"
        else:
            note = ", ".join(filter(None, ["PK" if c.primary_key else "", *[f"FK→{fk.target_fullname}" for fk in c.foreign_keys]]))
        md.append(f"| {c.name} | {c.type} | {'yes' if c.nullable else 'no'} | {note} |")
    cks = [str(x.sqltext) for x in t.constraints if x.__class__.__name__ == "CheckConstraint"]
    if cks:
        md += ["", "Constraints: " + "; ".join(f"`{c}`" for c in cks)]
    md.append("")

for d in (root / "contracts", shared / "contracts"):
    d.mkdir(parents=True, exist_ok=True)
    (d / "openapi.json").write_text(spec)
    (d / "data-models.md").write_text("\n".join(md))
for name in ("evidence-schema.json", "architecture-schema.json"):
    src = root / "contracts" / name
    if src.exists():
        shutil.copy(src, shared / "contracts" / name)
print("contracts exported")
