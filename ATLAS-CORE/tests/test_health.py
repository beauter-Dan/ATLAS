def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["data"]["status"] == "ok"


def test_error_format(client):
    r = client.get("/api/v1/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "http_404"
