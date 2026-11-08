"""Export OpenAPI spec to contracts/ and ../ATLAS-SHARED/contracts/."""
import json, pathlib
from app.main import app

spec = json.dumps(app.openapi(), indent=2)
root = pathlib.Path(__file__).resolve().parents[1]
for p in (root / "contracts", root.parent / "ATLAS-SHARED" / "contracts"):
    p.mkdir(parents=True, exist_ok=True)
    (p / "openapi.json").write_text(spec)
print("OpenAPI exported")
