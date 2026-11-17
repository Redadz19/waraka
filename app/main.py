import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.models import Device, EmailOTP, License, Payment, PaymentWebhookEvent
from app.schemas import (
    LicenseCreate, OTPRequest, ActivateRequest, DeactivateRequest, VerifyRequest,
    PaymentCheckoutRequest,
)
from app.security import (
    hash_otp, hash_serial, new_serial, public_key_b64, sign_payload,
    encrypt_license_serial, decrypt_license_serial,
)
from app.emailer import send_otp, send_license


app = FastAPI(title=settings.app_name, version="1.1.0")
origins = ["*"] if settings.cors_origins == "*" else settings.cors_origins.split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=origins != ["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Admin-API-Key"],
)


def utcnow():
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def admin_guard(x_admin_api_key: str | None):
    if not settings.admin_api_key or not x_admin_api_key or not secrets.compare_digest(x_admin_api_key, settings.admin_api_key):
        raise HTTPException(401, "Unauthorized")


def build_activation_payload(lic: License, device: Device, email: str, now: datetime) -> dict:
    """Build the exact data covered by the Ed25519 activation signature."""
    expires_at = ensure_utc(lic.expires_at).isoformat() if lic.expires_at else None
    return {
        "license_id": lic.id,
        "email": email,
        "device_id": device.device_id,
        "issued_at": ensure_utc(now).isoformat(),
        "expires_at": expires_at,
        "offline_grace_days": settings.offline_grace_days,
        "recheck_days": settings.recheck_days,
    }


@app.on_event("startup")
def startup():
    if settings.environment == "development":
        Base.metadata.create_all(bind=engine)


@app.get("/v1/public-key")
def get_public_key():
    try:
        return {"algorithm": "Ed25519", "public_key": public_key_b64()}
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(503, "Signing key is not configured") from exc


@app.get("/health")
def health():
    return {"status": "ok", "service": "waraka-licensing", "version": app.version}


@app.post("/v1/admin/licenses")
def create_license(body: LicenseCreate, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    admin_guard(x_admin_api_key)
    serial = new_serial()
    expires = body.expires_at
    lic = License(serial_hash=hash_serial(serial), email=str(body.email).lower(), expires_at=expires)
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return {"id": lic.id, "serial": serial, "email": lic.email, "expires_at": lic.expires_at}


@app.post("/v1/admin/licenses/{license_id}/revoke")
def revoke_license(license_id: str, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    admin_guard(x_admin_api_key)
    lic = db.get(License, license_id)
    if not lic:
        raise HTTPException(404, "License not found")
    lic.active = False
    db.commit()
    return {"revoked": True, "license_id": lic.id}


@app.post("/v1/otp/request")
def request_otp(body: OTPRequest, db: Session = Depends(get_db)):
    email = str(body.email).lower()
    lic = db.scalar(select(License).where(
        License.serial_hash == hash_serial(body.serial),
        License.email == email,
        License.active.is_(True),
    ).with_for_update())
    if not lic or (lic.expires_at and ensure_utc(lic.expires_at) <= utcnow()):
        raise HTTPException(403, "License credentials are invalid or expired")

    now = utcnow()
    recent = db.scalar(
        select(EmailOTP)
        .where(EmailOTP.license_id == lic.id, EmailOTP.created_at > now - timedelta(seconds=settings.otp_resend_seconds))
        .order_by(desc(EmailOTP.created_at))
    )
    if recent:
        raise HTTPException(429, "Please wait before requesting another code")

    code = f"{secrets.randbelow(1_000_000):06d}"
    try:
        code_hash = hash_otp(code)
    except RuntimeError as exc:
        raise HTTPException(503, "Email verification is not configured") from exc

    otp = EmailOTP(
        license_id=lic.id,
        email=email,
        code_hash=code_hash,
        expires_at=now + timedelta(seconds=settings.otp_ttl_seconds),
    )
    db.add(otp)
    db.commit()
    try:
        send_otp(email, code)
    except Exception as exc:
        # Keep a consumed record so repeated delivery failures cannot bypass
        # the per-license resend cooldown.
        otp.consumed = True
        db.commit()
        raise HTTPException(503, "Email delivery is unavailable") from exc
    return {"status": "sent", "expires_in": settings.otp_ttl_seconds}


@app.post("/v1/license/activate")
def activate(body: ActivateRequest, db: Session = Depends(get_db)):
    email = str(body.email).lower()
    lic = db.scalar(select(License).where(
        License.serial_hash == hash_serial(body.serial),
        License.email == email,
        License.active.is_(True),
    ).with_for_update())
    now = utcnow()
    if not lic or (lic.expires_at and ensure_utc(lic.expires_at) <= now):
        raise HTTPException(403, "License is invalid or expired")

    otp = db.scalar(
        select(EmailOTP)
        .where(
            EmailOTP.license_id == lic.id,
            EmailOTP.email == email,
            EmailOTP.consumed.is_(False),
        )
        .order_by(desc(EmailOTP.created_at))
    )
    if not otp or ensure_utc(otp.expires_at) <= now or otp.attempts >= settings.otp_max_attempts:
        raise HTTPException(403, "Verification code is missing, expired, or locked")

    try:
        supplied_hash = hash_otp(body.code)
    except RuntimeError as exc:
        raise HTTPException(503, "Email verification is not configured") from exc

    if not secrets.compare_digest(otp.code_hash, supplied_hash):
        otp.attempts += 1
        db.commit()
        raise HTTPException(403, "Invalid verification code")

    device = db.scalar(select(Device).where(Device.license_id == lic.id, Device.device_id == body.device_id))
    if not device or device.revoked:
        active_count = db.scalar(
            select(func.count()).select_from(Device).where(
                Device.license_id == lic.id,
                Device.revoked.is_(False),
            )
        ) or 0
        if active_count >= settings.max_devices_per_license:
            db.commit()
            raise HTTPException(409, "Maximum number of activated devices reached")
        if device:
            # A user-deactivated device may be activated again without creating
            # a duplicate row or bypassing the active-device limit.
            device.revoked = False
            device.device_name = body.device_name or device.device_name
            device.activated_at = now
        else:
            device = Device(license_id=lic.id, device_id=body.device_id, device_name=body.device_name)
            db.add(device)

    device.last_seen_at = now
    payload = build_activation_payload(lic, device, email, now)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        signature = sign_payload(encoded)
    except (RuntimeError, ValueError) as exc:
        db.rollback()
        raise HTTPException(503, "Signing key is not configured") from exc

    otp.consumed = True
    db.commit()
    return {"license": payload, "signature": signature}


@app.post("/v1/license/verify")
def verify(body: VerifyRequest, db: Session = Depends(get_db)):
    lic = db.scalar(select(License).where(
        License.serial_hash == hash_serial(body.serial),
        License.email == str(body.email).lower(),
        License.active.is_(True),
    ))
    now = utcnow()
    if not lic or (lic.expires_at and ensure_utc(lic.expires_at) <= now):
        raise HTTPException(403, "License is invalid or expired")
    device = db.scalar(select(Device).where(
        Device.license_id == lic.id,
        Device.device_id == body.device_id,
        Device.revoked.is_(False),
    ))
    if not device:
        raise HTTPException(403, "Device is not activated")
    device.last_seen_at = now
    db.commit()
    return {"valid": True, "server_time": now.isoformat()}


@app.post("/v1/license/deactivate")
def deactivate(body: DeactivateRequest, db: Session = Depends(get_db)):
    lic = db.scalar(select(License).where(
        License.serial_hash == hash_serial(body.serial),
        License.email == str(body.email).lower(),
    ))
    if not lic:
        raise HTTPException(404, "License not found")
    device = db.scalar(select(Device).where(
        Device.license_id == lic.id,
        Device.device_id == body.device_id,
        Device.revoked.is_(False),
    ))
    if not device:
        raise HTTPException(404, "Active device not found")
    device.revoked = True
    db.commit()
    return {"deactivated": True}



def _chargily_checkout_endpoint() -> str:
    mode = settings.chargily_mode.strip().lower()
    if mode == "test":
        return "https://pay.chargily.net/test/api/v2/checkouts"
    if mode == "live":
        return "https://pay.chargily.net/api/v2/checkouts"
    raise HTTPException(503, "Chargily mode must be test or live")


def _public_base_url() -> str:
    value = settings.public_base_url.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise HTTPException(503, "PUBLIC_BASE_URL must be a valid HTTPS URL")
    return value


def _send_paid_license(payment: Payment, db: Session) -> None:
    if not payment.license_serial_ciphertext:
        return
    payment.license_email_attempts += 1
    try:
        serial = decrypt_license_serial(payment.license_serial_ciphertext)
        send_license(payment.customer_email, serial)
        payment.license_email_sent_at = utcnow()
        payment.license_email_last_error = None
    except Exception:
        # Payment is already committed. Keep the encrypted serial so an
        # administrator can safely retry delivery without issuing a new key.
        payment.license_email_last_error = "Email delivery failed; retry is available"
    db.commit()


@app.post("/v1/payments/chargily/checkout")
def create_chargily_checkout(
    body: PaymentCheckoutRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(get_db),
):
    if not settings.chargily_api_secret_key:
        raise HTTPException(503, "Chargily API credentials are not configured")
    if settings.waraka_price_dzd <= 0:
        raise HTTPException(503, "WARAKA purchase price has not been configured")
    if not idempotency_key or not 16 <= len(idempotency_key) <= 80 or not re.fullmatch(r"[A-Za-z0-9._:-]+", idempotency_key):
        raise HTTPException(400, "A valid Idempotency-Key header is required")
    email = str(body.email).lower()
    key_hash = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()

    existing = db.scalar(
        select(Payment).where(Payment.idempotency_key == key_hash).with_for_update()
    )
    if existing:
        if existing.customer_email != email or existing.amount_dzd != settings.waraka_price_dzd:
            raise HTTPException(409, "Idempotency key was already used for a different purchase")
        if existing.checkout_url:
            return {
                "payment_id": existing.id,
                "status": existing.status,
                "checkout_url": existing.checkout_url,
                "amount": existing.amount_dzd,
                "currency": "dzd",
                "reused": True,
            }
        raise HTTPException(409, "This purchase request is already being processed; use a new key only after support review")

    _public_base_url()
    _chargily_checkout_endpoint()
    payment = Payment(
        provider="chargily",
        idempotency_key=key_hash,
        customer_email=email,
        amount_dzd=settings.waraka_price_dzd,
        currency="DZD",
        status="pending",
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)

    base_url = _public_base_url()
    payload = {
        "amount": payment.amount_dzd,
        "currency": "dzd",
        "payment_method": body.payment_method,
        "success_url": f"{base_url}/payments/success",
        "failure_url": f"{base_url}/payments/failure",
        "webhook_endpoint": f"{base_url}/v1/payments/chargily/webhook",
        "description": f"WARAKA lifetime license purchase {payment.id}",
        "locale": body.locale,
        "chargily_pay_fees_allocation": "merchant",
    }
    try:
        response = httpx.post(
            _chargily_checkout_endpoint(),
            json=payload,
            headers={
                "Authorization": f"Bearer {settings.chargily_api_secret_key}",
                "Content-Type": "application/json",
            },
            timeout=25.0,
        )
    except httpx.TimeoutException as exc:
        payment.provider_metadata = {"request_state": "timeout_unknown"}
        db.commit()
        raise HTTPException(504, "Payment gateway response timed out; do not repeat this request") from exc
    except httpx.RequestError as exc:
        payment.provider_metadata = {"request_state": "connection_error"}
        db.commit()
        raise HTTPException(502, "Could not connect to the payment gateway") from exc

    if response.status_code >= 400:
        payment.status = "failed"
        payment.provider_metadata = {"gateway_http_status": response.status_code}
        db.commit()
        raise HTTPException(502, "Chargily rejected the checkout request")

    try:
        checkout = response.json()
    except ValueError as exc:
        payment.provider_metadata = {"request_state": "invalid_gateway_response"}
        db.commit()
        raise HTTPException(502, "Payment gateway returned an invalid response") from exc

    checkout_id = checkout.get("id")
    checkout_url = checkout.get("checkout_url")
    checkout_host = urlparse(checkout_url).hostname if isinstance(checkout_url, str) else None
    expected_live = settings.chargily_mode.strip().lower() == "live"
    actual_live = checkout.get("livemode")
    if isinstance(actual_live, str):
        actual_live = actual_live.strip().lower() == "true"
    if (
        not isinstance(checkout_id, str)
        or not checkout_id
        or not isinstance(checkout_url, str)
        or urlparse(checkout_url).scheme != "https"
        or not checkout_host
        or not (checkout_host == "chargily.dz" or checkout_host.endswith(".chargily.dz")
                or checkout_host == "chargily.net" or checkout_host.endswith(".chargily.net"))
        or checkout.get("amount") != payment.amount_dzd
        or str(checkout.get("currency", "")).lower() != "dzd"
        or actual_live is not expected_live
    ):
        payment.status = "failed"
        payment.provider_metadata = {"request_state": "gateway_response_validation_failed"}
        db.commit()
        raise HTTPException(502, "Payment gateway response did not match the expected purchase")

    payment.provider_reference = checkout_id
    payment.checkout_url = checkout_url
    payment.provider_metadata = {
        "livemode": expected_live,
        "gateway_status": checkout.get("status"),
        "payment_method": body.payment_method,
    }
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Gateway checkout reference already exists") from exc

    return {
        "payment_id": payment.id,
        "status": payment.status,
        "checkout_url": payment.checkout_url,
        "amount": payment.amount_dzd,
        "currency": "dzd",
        "reused": False,
    }


@app.post("/v1/payments/chargily/webhook")
async def chargily_webhook(request: Request, db: Session = Depends(get_db)):
    if not settings.chargily_api_secret_key:
        raise HTTPException(503, "Payment webhook verification is not configured")
    raw_body = await request.body()
    if len(raw_body) > 1_000_000:
        raise HTTPException(413, "Webhook payload is too large")
    signature = request.headers.get("signature", "")
    if not signature:
        raise HTTPException(400, "Missing Chargily signature")
    expected_signature = hmac.new(
        settings.chargily_api_secret_key.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(403, "Invalid Chargily signature")
    try:
        event = json.loads(raw_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, "Invalid webhook JSON") from exc

    event_id = event.get("id")
    event_type = event.get("type")
    checkout = event.get("data")
    if not isinstance(event_id, str) or not event_id or not isinstance(event_type, str) or not isinstance(checkout, dict):
        raise HTTPException(400, "Invalid webhook event structure")
    if event_type not in {"checkout.paid", "checkout.failed", "checkout.canceled"}:
        return {"received": True, "ignored": True}

    livemode = event.get("livemode")
    if isinstance(livemode, str):
        livemode = livemode.strip().lower() == "true"
    if not isinstance(livemode, bool):
        raise HTTPException(400, "Missing payment environment flag")
    expected_live = settings.chargily_mode.strip().lower() == "live"
    if livemode is not expected_live:
        raise HTTPException(403, "Webhook belongs to a different Chargily environment")

    checkout_id = checkout.get("id")
    if not isinstance(checkout_id, str) or not checkout_id:
        raise HTTPException(400, "Missing checkout identifier")
    payment = db.scalar(
        select(Payment).where(
            Payment.provider == "chargily",
            Payment.provider_reference == checkout_id,
        ).with_for_update()
    )
    if not payment:
        raise HTTPException(404, "Payment record not found")

    duplicate = db.scalar(
        select(PaymentWebhookEvent).where(
            PaymentWebhookEvent.provider == "chargily",
            PaymentWebhookEvent.event_id == event_id,
        )
    )
    if duplicate:
        return {"received": True, "duplicate": True}

    if event_type == "checkout.paid":
        if checkout.get("status") != "paid":
            raise HTTPException(400, "Paid event has a non-paid checkout status")
        if checkout.get("amount") != payment.amount_dzd or str(checkout.get("currency", "")).upper() != payment.currency:
            raise HTTPException(400, "Paid checkout amount or currency does not match the order")
        if payment.status != "refunded":
            if not payment.license_id:
                try:
                    serial = new_serial()
                    license_record = License(
                        serial_hash=hash_serial(serial),
                        email=payment.customer_email,
                        active=True,
                        expires_at=None,
                    )
                    db.add(license_record)
                    db.flush()
                    payment.license_id = license_record.id
                    payment.license_serial_ciphertext = encrypt_license_serial(serial)
                except (RuntimeError, ValueError) as exc:
                    db.rollback()
                    raise HTTPException(503, "License serial encryption is not configured correctly") from exc
            payment.status = "paid"
            payment.paid_at = payment.paid_at or utcnow()
    else:
        if payment.status not in {"paid", "refunded"}:
            payment.status = "failed"

    db.add(PaymentWebhookEvent(
        provider="chargily",
        event_id=event_id,
        payment_id=payment.id,
        event_type=event_type,
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return {"received": True, "duplicate": True}

    if event_type == "checkout.paid" and payment.status == "paid" and payment.license_email_sent_at is None:
        _send_paid_license(payment, db)
    return {"received": True, "processed": True}


@app.get("/v1/payments/{payment_id}")
def get_payment_status(payment_id: str, db: Session = Depends(get_db)):
    payment = db.get(Payment, payment_id)
    if not payment:
        raise HTTPException(404, "Payment not found")
    return {
        "payment_id": payment.id,
        "status": payment.status,
        "license_issued": payment.license_id is not None,
        "license_email_sent": payment.license_email_sent_at is not None,
    }


@app.post("/v1/admin/payments/{payment_id}/resend-license")
def resend_license_email(
    payment_id: str,
    x_admin_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    admin_guard(x_admin_api_key)
    payment = db.get(Payment, payment_id)
    if not payment or payment.status != "paid" or not payment.license_serial_ciphertext:
        raise HTTPException(404, "Paid license delivery record not found")
    _send_paid_license(payment, db)
    if payment.license_email_sent_at is None:
        raise HTTPException(503, "License email delivery failed")
    return {"sent": True, "payment_id": payment.id}


@app.get("/payments/success", response_class=PlainTextResponse)
def payment_success_return():
    return "Thank you. Payment confirmation is processed securely by Chargily. Your WARAKA lifetime license will be sent to your email after confirmation."


@app.get("/payments/failure", response_class=PlainTextResponse)
def payment_failure_return():
    return "The payment was not completed. No WARAKA license has been issued."
