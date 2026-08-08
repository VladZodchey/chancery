async def test_health_endpoint(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_index_and_static(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "New paste" in r.text
    assert (await client.get("/static/style.css")).status_code == 200


async def test_create_redirect_and_view(client):
    r = await client.post("/", data={"content": "hello web"})
    assert r.status_code == 303
    loc = r.headers["location"]
    assert (await client.get(loc)).status_code == 200
    assert "hello web" in (await client.get(loc)).text


async def test_web_missing_paste_is_404_page(client):
    r = await client.get("/doesnotexist")
    assert r.status_code == 404
    assert "404" in r.text


async def test_web_burn_flow(client):
    r = await client.post("/", data={"content": "burn me", "burn_after_read": "on"})
    assert r.status_code == 200
    assert "burn-after-read" in r.text
    link = next(s.split('"')[0] for s in r.text.split('href="') if s.startswith("http"))
    assert "burn me" in (await client.get(link)).text
    assert (await client.get(link)).status_code == 404


async def test_web_plain_paste_still_redirects(client):
    r = await client.post("/", data={"content": "hello web"})
    assert r.status_code == 303
    assert r.headers["location"].startswith("/")


async def test_web_encrypted_flow(client):
    r = await client.post("/", data={"content": "encrypted", "password": "pw"})
    loc = r.headers["location"]
    page = await client.get(loc)
    assert page.status_code == 200
    assert "password-protected" in page.text
    assert "encrypted" not in page.text

    wrong = await client.post(f"{loc}/unlock", data={"password": "bad"})
    assert wrong.status_code == 403

    good = await client.post(f"{loc}/unlock", data={"password": "pw"})
    assert good.status_code == 200
    assert "encrypted" in good.text


async def test_web_expiry_form(client):
    r = await client.post("/", data={"content": "temp", "ttl_seconds": "3600"})
    loc = r.headers["location"]
    page = await client.get(loc)
    assert page.status_code == 200
    assert "expires" in page.text


async def test_raw_plain(client):
    r = await client.post("/api/pastes", json={"content": "curl me"})
    paste_id = r.json()["id"]
    raw = await client.get(f"/raw/{paste_id}")
    assert raw.status_code == 200
    assert raw.text == "curl me"


async def test_raw_encrypted_rejected(client):
    r = await client.post("/api/pastes", json={"content": "secret", "password": "pw"})
    paste_id = r.json()["id"]
    assert (await client.get(f"/raw/{paste_id}")).status_code == 401


async def test_api_create_and_get(client):
    r = await client.post("/api/pastes", json={"content": "api paste", "ttl_seconds": 60})
    assert r.status_code == 201
    body = r.json()
    assert body["url"] == f"http://testserver/{body['id']}"
    got = await client.get(f"/api/pastes/{body['id']}")
    assert got.status_code == 200
    assert got.json()["content"] == "api paste"
    assert got.json()["expires_at"] is not None


async def test_api_password_flow(client):
    r = await client.post("/api/pastes", json={"content": "c", "password": "pw"})
    paste_id = r.json()["id"]
    assert (await client.get(f"/api/pastes/{paste_id}")).status_code == 401
    assert (
        await client.get(f"/api/pastes/{paste_id}", params={"password": "bad"})
    ).status_code == 403
    assert (
        await client.get(f"/api/pastes/{paste_id}", params={"password": "pw"})
    ).status_code == 200


async def test_api_burn_via_api(client):
    r = await client.post("/api/pastes", json={"content": "one shot", "burn_after_read": True})
    paste_id = r.json()["id"]
    assert (await client.get(f"/api/pastes/{paste_id}")).json()["content"] == "one shot"
    assert (await client.get(f"/api/pastes/{paste_id}")).status_code == 404


async def test_api_errors(client):
    assert (await client.get("/api/pastes/doesnotexist")).status_code == 404
    assert (await client.post("/api/pastes", json={"content": "\x00bad"})).status_code == 400
    assert (await client.post("/api/pastes", json={"content": "\x1b]0;evil\x07"})).status_code == 400
    assert (await client.post("/api/pastes", json={"content": "x" * 2000})).status_code == 413
    assert (
        await client.post("/api/pastes", json={"content": "x", "ttl_seconds": -1})
    ).status_code == 400
