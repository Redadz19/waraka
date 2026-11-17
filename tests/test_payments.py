import hashlib
import hmac
import json

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.config import settings
from app.database import Base
from app.models import License, Payment, PaymentWebhookEvent


@pytest.fixture
def payment_api():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_get_db
    with TestClient(main.app) as client:
        yield client, Session
    main.app.dependency_overrides.clear()
    engine.dispose()


def configure_payment_settings(monkeypatch):
    monkeypatch.setattr(settings, "chargily_api_secret_key", "test_sk_waraka_secret")
    monkeypatch.setattr(settings, "chargily_mode", "test")
    monkeypatch.setattr(settings, "waraka_price_dzd", 2400)
    monkeypatch.setattr(settings, "public_base_url", "https://waraka.example")
    monkeypatch.setattr(
        settings,
        "license_serial_encryption_key",
        Fernet.generate_key().decode("ascii"),
    )


def sign_event(payload: bytes) -> str:
    return hmac.new(
        settings.chargily_api_secret_key.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()


def test_checkout_uses_server_price_and_is_idempotent(payment_api, monkeypatch):
    configure_payment_settings(monkeypatch)
    calls = []

    class FakeResponse:
        status_code = 201

        @staticmethod
        def json():
            return {
                "id": "chargily-checkout-001",
                "checkout_url": "https://pay.chargily.dz/test/checkouts/001/pay",
                "amount": 2400,
                "currency": "dzd",
                "livemode": False,
                "status": "pending",
            }

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr(main.httpx, "post", fake_post)
    client, Session = payment_api
    headers = {"Idempotency-Key": "waraka-order-unique-001"}
    body = {"email": "Buyer@Example.com", "payment_method": "cib", "locale": "ar"}

    first = client.post("/v1/payments/chargily/checkout", json=body, headers=headers)
    second = client.post("/v1/payments/chargily/checkout", json=body, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["checkout_url"].endswith("/001/pay")
    assert second.json()["reused"] is True
    assert len(calls) == 1
    assert calls[0][1]["json"]["amount"] == 2400
    assert calls[0][1]["json"]["currency"] == "dzd"
    assert calls[0][1]["json"]["payment_method"] == "cib"

    db = Session()
    assert db.scalar(select(func.count()).select_from(Payment)) == 1
    payment = db.scalar(select(Payment))
    assert payment.customer_email == "buyer@example.com"
    assert payment.amount_dzd == 2400
    assert payment.status == "pending"
    db.close()


def test_signed_paid_webhook_issues_one_lifetime_license(payment_api, monkeypatch):
    configure_payment_settings(monkeypatch)
    sent = []
    monkeypatch.setattr(main, "send_license", lambda email, serial: sent.append((email, serial)))
    client, Session = payment_api

    db = Session()
    payment = Payment(
        provider="chargily",
        provider_reference="chargily-checkout-paid-001",
        idempotency_key="a" * 64,
        customer_email="buyer@example.com",
        amount_dzd=2400,
        currency="DZD",
        status="pending",
    )
    db.add(payment)
    db.commit()
    payment_id = payment.id
    db.close()

    event = {
        "id": "chargily-event-paid-001",
        "entity": "event",
        "livemode": False,
        "type": "checkout.paid",
        "data": {
            "id": "chargily-checkout-paid-001",
            "entity": "checkout",
            "amount": 2400,
            "currency": "dzd",
            "status": "paid",
        },
    }
    raw = json.dumps(event, separators=(",", ":")).encode("utf-8")
    headers = {"signature": sign_event(raw)}

    first = client.post("/v1/payments/chargily/webhook", content=raw, headers=headers)
    duplicate = client.post("/v1/payments/chargily/webhook", content=raw, headers=headers)

    assert first.status_code == 200
    assert first.json()["processed"] is True
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert len(sent) == 1
    assert sent[0][0] == "buyer@example.com"

    db = Session()
    stored_payment = db.get(Payment, payment_id)
    assert stored_payment.status == "paid"
    assert stored_payment.license_id is not None
    assert stored_payment.license_email_sent_at is not None
    license_record = db.get(License, stored_payment.license_id)
    assert license_record is not None
    assert license_record.expires_at is None
    assert license_record.email == "buyer@example.com"
    assert db.scalar(select(func.count()).select_from(License)) == 1
    assert db.scalar(select(func.count()).select_from(PaymentWebhookEvent)) == 1
    db.close()


def test_webhook_rejects_invalid_signature(payment_api, monkeypatch):
    configure_payment_settings(monkeypatch)
    client, _ = payment_api
    raw = b'{"id":"event-1","type":"checkout.paid","livemode":false,"data":{"id":"checkout-1"}}'

    response = client.post(
        "/v1/payments/chargily/webhook",
        content=raw,
        headers={"signature": "0" * 64},
    )

    assert response.status_code == 403


def test_webhook_rejects_amount_mismatch_without_issuing_license(payment_api, monkeypatch):
    configure_payment_settings(monkeypatch)
    client, Session = payment_api
    db = Session()
    payment = Payment(
        provider="chargily",
        provider_reference="chargily-checkout-mismatch",
        idempotency_key="b" * 64,
        customer_email="buyer@example.com",
        amount_dzd=2400,
        currency="DZD",
        status="pending",
    )
    db.add(payment)
    db.commit()
    db.close()

    event = {
        "id": "chargily-event-mismatch",
        "livemode": False,
        "type": "checkout.paid",
        "data": {
            "id": "chargily-checkout-mismatch",
            "amount": 100,
            "currency": "dzd",
            "status": "paid",
        },
    }
    raw = json.dumps(event, separators=(",", ":")).encode("utf-8")
    response = client.post(
        "/v1/payments/chargily/webhook",
        content=raw,
        headers={"signature": sign_event(raw)},
    )

    assert response.status_code == 400
    db = Session()
    assert db.scalar(select(func.count()).select_from(License)) == 0
    db.close()
