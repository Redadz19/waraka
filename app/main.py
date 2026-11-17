import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import Base, engine, get_db
from app.models import Device, EmailOTP, License
from app.schemas import LicenseCreate, OTPRequest, ActivateRequest, DeactivateRequest, VerifyRequest
from app.security import hash_otp, hash_serial, new_serial, public_key_b64, sign_payload
from app.emailer import send_otp


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

    otp.attempts += 1
    if not secrets.compare_digest(otp.code_hash, supplied_hash):
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
