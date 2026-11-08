from app.services import app_intel, db_intel

SRC = {"app/main.py": '''
from fastapi import FastAPI, Depends
import jwt, boto3, os
app = FastAPI()
app.add_middleware(CORSMiddleware)
KEY = os.environ["DB_URL"]
@app.get("/health")
def h(): ...
@app.post("/orders/{order_id}/cancel")
def cancel(order_id: int, user=Depends(get_current_user)): ...
@app.delete("/users/{id}")
def rm(id): ...
''', "web/server.js": "const express=require('express'); app.get('/api/items/:id', verifyToken, h); fetch('https://api.stripe.com/v1')"}

SQL = """
CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(200) NOT NULL, password_hash TEXT);
CREATE TABLE orders (id SERIAL, user_id INT NOT NULL REFERENCES users(id), total NUMERIC(10,2),
  PRIMARY KEY (id), FOREIGN KEY (user_id) REFERENCES users(id));
"""


def test_app_analysis():
    r = app_intel.analyze_files(SRC)
    assert {"Python", "JavaScript"} <= set(r["languages"])
    assert {"FastAPI", "Express"} <= set(r["frameworks"])
    by = {(x["method"], x["path"]): x for x in r["routes"]}
    assert by[("POST", "/orders/{order_id}/cancel")]["auth_required"] is True
    assert by[("DELETE", "/users/{id}")]["auth_required"] is None      # unknown, never assumed
    assert "JWT" in r["authentication_mechanisms"] and "Stripe" in r["external_integrations"]
    assert "DB_URL" in r["configuration_variables"]


def test_schema_parse():
    r = db_intel.parse_ddl(SQL)
    assert r["technology"] == "postgresql" and r["technology_confidence"] == "low"
    t = {x["name"]: x for x in r["tables"]}
    assert t["users"]["sensitivity"] == "restricted" and t["users"]["primary_key"] == ["id"]
    assert t["orders"]["foreign_keys"][0]["ref_table"] == "users" and t["orders"]["ownership_columns"] == ["user_id"]


def test_no_tech_guess_without_syntax():
    assert db_intel.parse_ddl("CREATE TABLE a (id INT);")["technology"] == "unknown"


def test_routes_are_not_duplicated_across_frameworks():
    r = app_intel.analyze_files({"a.py": '@app.get("/x")\ndef f(): ...\n', "b.js": "app.get('/x', h)\nrouter.post('/y', h)\n"})
    keys = [(x["file"], x["method"], x["path"]) for x in r["routes"]]
    assert sorted(keys) == [("a.py", "GET", "/x"), ("b.js", "GET", "/x"), ("b.js", "POST", "/y")] and len(keys) == len(set(keys))
