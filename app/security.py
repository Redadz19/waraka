import base64, hashlib, secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.config import settings

def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def new_serial() -> str:
    raw = secrets.token_hex(16).upper()
    return "-".join(raw[i:i+4] for i in range(0, len(raw), 4))

def sign_payload(payload: bytes) -> str:
    if not settings.license_private_key_b64:
        raise RuntimeError("LICENSE_PRIVATE_KEY_B64 is not configured")
    raw = base64.b64decode(settings.license_private_key_b64)
    return base64.b64encode(Ed25519PrivateKey.from_private_bytes(raw).sign(payload)).decode("ascii")
