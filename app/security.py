import base64
import hashlib
import hmac
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.config import settings


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_serial(serial: str) -> str:
    return hashlib.sha256(serial.strip().upper().encode("utf-8")).hexdigest()


def hash_otp(code: str) -> str:
    if len(settings.otp_secret) < 32:
        raise RuntimeError("OTP_SECRET must contain at least 32 characters")
    return hmac.new(settings.otp_secret.encode("utf-8"), code.encode("ascii"), hashlib.sha256).hexdigest()


def new_serial() -> str:
    raw = secrets.token_hex(16).upper()
    return "WRK-" + "-".join(raw[i:i+4] for i in range(0, len(raw), 4))


def _private_key() -> Ed25519PrivateKey:
    if not settings.license_private_key_b64:
        raise RuntimeError("LICENSE_PRIVATE_KEY_B64 is not configured")
    raw = base64.b64decode(settings.license_private_key_b64, validate=True)
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_payload(payload: bytes) -> str:
    key = _private_key()
    # Fail closed if an explicitly configured public key does not match.
    public_key_b64()
    return base64.b64encode(key.sign(payload)).decode("ascii")


def public_key_b64() -> str:
    raw = _private_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if settings.license_public_key_b64:
        configured = base64.b64decode(settings.license_public_key_b64, validate=True)
        if len(configured) != 32 or not hmac.compare_digest(raw, configured):
            raise RuntimeError("LICENSE_PUBLIC_KEY_B64 does not match LICENSE_PRIVATE_KEY_B64")
        raw = configured
    return base64.b64encode(raw).decode("ascii")



def encrypt_license_serial(serial: str) -> str:
    if not settings.license_serial_encryption_key:
        raise RuntimeError("LICENSE_SERIAL_ENCRYPTION_KEY is not configured")
    return Fernet(settings.license_serial_encryption_key.encode("ascii")).encrypt(
        serial.encode("utf-8")
    ).decode("ascii")


def decrypt_license_serial(ciphertext: str) -> str:
    if not settings.license_serial_encryption_key:
        raise RuntimeError("LICENSE_SERIAL_ENCRYPTION_KEY is not configured")
    return Fernet(settings.license_serial_encryption_key.encode("ascii")).decrypt(
        ciphertext.encode("ascii")
    ).decode("utf-8")
