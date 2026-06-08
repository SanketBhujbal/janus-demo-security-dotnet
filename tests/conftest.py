import os, time, requests, pytest

BASE = os.environ.get("TARGET_URL", "http://localhost:8080")

@pytest.fixture(scope="session", autouse=True)
def wait_for_app():
    for _ in range(30):
        try:
            if requests.get(f"{BASE}/health", timeout=1).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.5)
    pytest.fail(f"App at {BASE} did not become ready")

@pytest.fixture(scope="session")
def alice_token():
    r = requests.post(f"{BASE}/api/auth/login",
                      json={"username": "alice", "password": "alice-pw"}, timeout=5)
    assert r.status_code == 200
    return r.json()["token"]
