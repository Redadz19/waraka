"""Generate Ed25519 keys for WARAKA license signatures."""
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("LICENSE_PRIVATE_KEY_B64=" + base64.b64encode(private).decode())
print("LICENSE_PUBLIC_KEY_B64=" + base64.b64encode(public).decode())
print("Keep the private key only in Render secrets; embed the public key in the Windows client.")
