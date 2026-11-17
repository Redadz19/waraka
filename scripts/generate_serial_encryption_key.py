"""Generate a Fernet key for encrypting license serials at rest."""
from cryptography.fernet import Fernet

print("LICENSE_SERIAL_ENCRYPTION_KEY=" + Fernet.generate_key().decode("ascii"))
print("Store this key only in the WARAKA API environment secrets. Never commit it.")
