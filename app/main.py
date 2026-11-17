import json, secrets
from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, desc, func
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db, Base, engine
from app.models import Device, EmailOTP, License
from app.schemas import LicenseCreate, OTPRequest, OTPVerifyRequest, ActivateRequest, DeactivateRequest, VerifyRequest
from app.security import hash_value, hash_serial, sign_payload, new_serial, public_key_b64
from app.emailer import send_otp

app = FastAPI(title=settings.app_name, version="1.0.0")
origins = ["*"] if settings.cors_origins == "*" else settings.cors_origins.split(",")
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=origins != ["*"], allow_methods=["GET","POST"], allow_headers=["Authorization","Content-Type"])

def utcnow():
    return datetime.now(timezone.utc)

def admin_guard(x_admin_api_key: str | None):
    if not settings.admin_api_key or not x_admin_api_key or not secrets.compare_digest(x_admin_api_key, settings.admin_api_key):
        raise HTTPException(401, "Unauthorized")

@app.on_event("startup")
def startup():
    if settings.environment == "development":
        Base.metadata.create_all(bind=engine)

@app.get("/v1/public-key")
def get_public_key():
    try:
        return {"algorithm": "Ed25519", "public_key": public_key_b64()}
    except Exception as exc:
        raise HTTPException(503, "Signing key is not configured") from exc

@app.get("/health")
def health():
    return {"status":"ok","service":"waraka-licensing","version":"1.0.0"}

@app.post("/v1/admin/licenses")
def create_license(body: LicenseCreate, x_admin_api_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    admin_guard(x_admin_api_key)
    serial = new_serial()
    expires = datetime.fromisoformat(body.expires_at) if body.expires_at else None
    lic = License(serial_hash=hash_serial(serial), email=str(body.email).lower(), expires_at=expires)
    db.add(lic); db.commit()
    return {"id":lic.id,"serial":serial,"email":lic.email,"expires_at":lic.expires_at}

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
    now = utcnow()
    recent = db.scalar(select(EmailOTP).where(EmailOTP.email == str(body.email).lower(), EmailOTP.created_at > now - timedelta(seconds=settings.otp_resend_seconds)).order_by(desc(EmailOTP.created_at)))
    if recent:
        raise HTTPException(429, "Please wait before requesting another code")
    code = f"{secrets.randbelow(1000000):06d}"
    otp = EmailOTP(email=str(body.email).lower(), code_hash=hash_value(code), expires_at=now + timedelta(seconds=settings.otp_ttl_seconds))
    db.add(otp); db.commit()
    try:
        send_otp(otp.email, code)
    except Exception as exc:
        db.delete(otp); db.commit()
        raise HTTPException(503, "Email delivery is unavailable") from exc
    return {"status":"sent","expires_in":settings.otp_ttl_seconds}

@app.post("/v1/otp/verify")
def verify_otp(body: OTPVerifyRequest, db: Session = Depends(get_db)):
    otp = db.scalar(select(EmailOTP).where(EmailOTP.email == str(body.email).lower(), EmailOTP.consumed.is_(False)).order_by(desc(EmailOTP.created_at)))
    if not otp or otp.expires_at < utcnow() or otp.attempts >= settings.otp_max_attempts:
        raise HTTPException(400, "Invalid or expired verification code")
    otp.attempts += 1
    if not secrets.compare_digest(otp.code_hash, hash_value(body.code)):
        db.commit()
        raise HTTPException(400, "Invalid or expired verification code")
    otp.consumed = True; db.commit()
    return {"verified":True}

@app.post("/v1/license/activate")
def activate(body: ActivateRequest, db: Session = Depends(get_db)):
    email = str(body.email).lower()
    lic = db.scalar(select(License).where(License.serial_hash == hash_serial(body.serial), License.email == email, License.active.is_(True)))
    if not lic or (lic.expires_at and lic.expires_at < utcnow()):
        raise HTTPException(403, "License is invalid or expired")
    device = db.scalar(select(Device).where(Device.license_id == lic.id, Device.device_id == body.device_id))
    if device and device.revoked:
        raise HTTPException(403, "This device has been revoked")
    if not device:
        active_count = db.scalar(select(func.count()).select_from(Device).where(Device.license_id == lic.id, Device.revoked.is_(False))) or 0
        if active_count >= settings.max_devices_per_license:
            raise HTTPException(409, "Maximum number of activated devices reached")
        device = Device(license_id=lic.id, device_id=body.device_id, device_name=body.device_name)
        db.add(device)
    device.last_seen_at = utcnow(); db.commit()
    payload = {"license_id":lic.id,"email":email,"device_id":device.device_id,"issued_at":utcnow().isoformat(),"offline_grace_days":14,"recheck_days":7}
    encoded = json.dumps(payload, sort_keys=True, separators=(",",":")).encode()
    try:
        signature = sign_payload(encoded)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return {"license":payload,"signature":signature}

@app.post("/v1/license/verify")
def verify(body: VerifyRequest, db: Session = Depends(get_db)):
    lic = db.scalar(select(License).where(License.serial_hash == hash_serial(body.serial), License.email == str(body.email).lower(), License.active.is_(True)))
    if not lic or (lic.expires_at and lic.expires_at < utcnow()):
        raise HTTPException(403, "License is invalid or expired")
    device = db.scalar(select(Device).where(Device.license_id == lic.id, Device.device_id == body.device_id, Device.revoked.is_(False)))
    if not device:
        raise HTTPException(403, "Device is not activated")
    device.last_seen_at = utcnow(); db.commit()
    return {"valid":True,"server_time":utcnow().isoformat()}

@app.post("/v1/license/deactivate")
def deactivate(body: DeactivateRequest, db: Session = Depends(get_db)):
    lic = db.scalar(select(License).where(License.serial_hash == hash_serial(body.serial)))
    if not lic:
        raise HTTPException(404, "License not found")
    device = db.scalar(select(Device).where(Device.license_id == lic.id, Device.device_id == body.device_id, Device.revoked.is_(False)))
    if not device:
        raise HTTPException(404, "Active device not found")
    device.revoked = True; db.commit()
    return {"deactivated":True}
