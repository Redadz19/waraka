import asyncio
import hashlib
import hmac
import json

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app import main
from app.config import settings
from app.database import Base
from app.models import License, Payment, PaymentWebhookEvent
from app.schemas import PaymentCheckoutRequest


@pytest.fixture
def payment_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = Session()
    yield db
    db.close()
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


def make_webhook_request(raw: bytes, signature: str) -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/payments/chargily/webhook",
        "raw_path": b"/v1/payments/chargily/webhook",
        "query_string": b"",
        "headers": [(b"signature", signature.encode("ascii"))],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 443),
    }

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    return Request(scope, receive)


def test_checkout_uses_server_price_and_is_idempotent(payment_db, monkeypatch):
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
    body = PaymentCheckoutRequest(
        email="Buyer@Example.com",
        payment_method="cib",
        locale="ar",
    )

    first = main.create_chargily_checkout(body, "waraka-order-unique-001", payment_db)
    second = main.create_chargily_checkout(body, "waraka-order-unique-001", payment_db)

    assert first["checkout_url"].endswith("/001/pay")
    assert second["reused"] is True
    assert len(calls) == 1
    assert calls[0][1]["json"]["amount"] == 2400
    assert calls[0][1]["json"]["currency"] == "dzd"
    assert calls[0][1]["json"]["payment_method"] == "cib"

    assert payment_db.scalar(select(func.count()).select_from(Payment)) == 1
    payment = payment_db.scalar(select(Payment))
    assert payment.customer_email == "buyer@example.com"
    assert payment.amount_dzd == 2400
    assert payment.status == "pending"


def test_signed_paid_webhook_issues_one_lifetime_license_and_deduplicates(payment_db, monkeypatch):
    configure_payment_settings(monkeypatch)
    sent = []
    monkeypatch.setattr(main, "send_license", lambda email, serial: sent.append((email, serial)))

    payment = Payment(
        provider="chargily",
        provider_reference="chargily-checkout-paid-001",
        idempotency_key="a" * 64,
        customer_email="buyer@example.com",
        amount_dzd=2400,
        currency="DZD",
        status="pending",
    )
    payment_db.add(payment)
    payment_db.commit()
    payment_id = payment.id

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
    signature = sign_event(raw)

    first = asyncio.run(main.chargily_webhook(make_webhook_request(raw, signature), payment_db))
    duplicate = asyncio.run(main.chargily_webhook(make_webhook_request(raw, signature), payment_db))

    assert first["processed"] is True
    assert duplicate["duplicate"] is True
    assert len(sent) == 1
    assert sent[0][0] == "buyer@example.com"

    stored_payment = payment_db.get(Payment, payment_id)
    assert stored_payment.status == "paid"
    assert stored_payment.license_id is not None
    assert stored_payment.license_email_sent_at is not None
    license_record = payment_db.get(License, stored_payment.license_id)
    assert license_record is not None
    assert license_record.expires_at is None
    assert license_record.email == "buyer@example.com"
    assert payment_db.scalar(select(func.count()).select_from(License)) == 1
    assert payment_db.scalar(select(func.count()).select_from(PaymentWebhookEvent)) == 1


def test_webhook_rejects_invalid_signature(payment_db, monkeypatch):
    configure_payment_settings(monkeypatch)
    raw = b'{"id":"event-1","type":"checkout.paid","livemode":false,"data":{"id":"checkout-1"}}'

    with pytest.raises(HTTPException) as error:
        asyncio.run(main.chargily_webhook(make_webhook_request(raw, "0" * 64), payment_db))

    assert error.value.status_code == 403


def test_webhook_rejects_amount_mismatch_without_issuing_license(payment_db, monkeypatch):
    configure_payment_settings(monkeypatch)
    payment = Payment(
        provider="chargily",
        provider_reference="chargily-checkout-mismatch",
        idempotency_key="b" * 64,
        customer_email="buyer@example.com",
        amount_dzd=2400,
        currency="DZD",
        status="pending",
    )
    payment_db.add(payment)
    payment_db.commit()

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

    with pytest.raises(HTTPException) as error:
        asyncio.run(main.chargily_webhook(
            make_webhook_request(raw, sign_event(raw)),
            payment_db,
        ))

    assert error.value.status_code == 400
    assert payment_db.scalar(select(func.count()).select_from(License)) == 0
