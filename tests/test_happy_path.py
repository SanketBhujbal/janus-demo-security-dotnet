"""Happy-path regression tests for the JANUS .NET security demo.

These run after every healer patch. Tests for findings 0-2 pass both before
and after the patch. The test for finding 3 (missing idempotency) is written
the OLD way — no Idempotency-Key header — which passes BEFORE the patch but
FAILS after the healer adds the header guard. That causes the validator to
mark finding 3 as FAILED, demonstrating JANUS's safety net.
"""
import os, requests
BASE = os.environ.get("TARGET_URL", "http://localhost:8080")


def _login(user="alice", pw="alice-pw"):
    r = requests.post(f"{BASE}/api/auth/login", json={"username": user, "password": pw}, timeout=5)
    assert r.status_code == 200, f"login {user} got {r.status_code}"
    return r.json()["token"]


def test_health():
    assert requests.get(f"{BASE}/health", timeout=5).status_code == 200


def test_login_alice():
    assert len(_login("alice", "alice-pw")) > 0


def test_login_bob():
    assert len(_login("bob", "bob-pw")) > 0


def test_charge_returns_transaction_id():
    token = _login()
    r = requests.post(f"{BASE}/api/payments/charge",
                      json={"amount": 25.00, "pan": "4111111111111111", "cvv": "123"},
                      headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert r.status_code == 200
    assert "transaction_id" in r.json()


def test_webhook_settles_order():
    r = requests.post(f"{BASE}/api/webhook/gateway",
                      json={"orderId": "order-1001", "amount": 75.00, "signature": "sig"},
                      timeout=5)
    assert r.status_code == 200
    assert r.json()["status"] == "settled"


def test_account_accessible():
    token = _login()
    r = requests.get(f"{BASE}/api/account/alice",
                     headers={"Authorization": f"Bearer {token}"}, timeout=5)
    assert r.status_code == 200
    assert "balance" in r.json()


def test_logs_endpoint():
    assert requests.get(f"{BASE}/api/payments/logs", timeout=5).status_code == 200


# ── Finding 3: MISSING IDEMPOTENCY ───────────────────────────────────────────
# This test calls /api/payments/transfer WITHOUT an Idempotency-Key header.
# BEFORE the healer's patch  → returns 200 (passes ✅)
# AFTER  the healer's patch  → returns 400 Bad Request (fails ❌)
# Validator sees test failure → marks finding 3 as FAILED → demo safety net.
def test_transfer_no_idempotency_key(alice_token):
    r = requests.post(
        f"{BASE}/api/payments/transfer",
        json={"fromAccount": "alice", "toAccount": "bob", "amount": 10.00},
        headers={"Authorization": f"Bearer {alice_token}"},
        # Deliberately NO Idempotency-Key header
        timeout=5,
    )
    assert r.status_code == 200, (
        f"Expected 200 but got {r.status_code} — "
        "if 400, the healer added an Idempotency-Key guard (which is the correct fix) "
        "but this test was written before the requirement existed"
    )
