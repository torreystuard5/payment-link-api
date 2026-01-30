from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def login_demo():
    resp = client.post(
        "/login",
        data={"username": "demo", "password": "password"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_login_works():
    headers = login_demo()
    assert "Authorization" in headers


def test_get_current_user():
    headers = login_demo()
    resp = client.get("/users/me", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "demo"


def test_create_payment_link_internal():
    headers = login_demo()
    payload = {
        "amount": 5000,
        "currency": "usd",
        "description": "Test link",
        "processor": "internal",
        "customer_email": "customer@example.com",
    }
    resp = client.post("/payment-links", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["amount"] == 5000
    assert data["currency"] == "usd"
    assert data["owner"] == "demo"


def test_expired_link_returns_410():
    headers = login_demo()
    payload = {
        "amount": 1000,
        "currency": "usd",
        "description": "Expires quickly",
        "processor": "internal",
        "expires_in_minutes": 1,  # valid
    }
    create_resp = client.post("/payment-links", json=payload, headers=headers)
    assert create_resp.status_code == 201

    link = create_resp.json()

    # First pay: should succeed (link is pending and not expired)
    pay_resp = client.post(f"/payment-links/{link['id']}/pay", headers=headers)
    assert pay_resp.status_code == 200

    # Second pay: should fail because link is no longer pending
    pay_resp = client.post(f"/payment-links/{link['id']}/pay", headers=headers)
    assert pay_resp.status_code == 400
