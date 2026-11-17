# WARAKA — Licensing Service

FastAPI backend for the WARAKA Windows PDF application.

## Included
- Administrator-protected license issuance
- Serial + email license binding
- PostgreSQL/Neon support and Alembic migration
- Email OTP (10-minute validity, 60-second resend interval, five attempts)
- Three active devices per license
- Device activation, verification and deactivation
- Ed25519-signed activation payloads
- Render blueprint and GitHub Actions CI

## Local setup
1. Python 3.12+
2. Create and activate a virtual environment.
3. Install: `pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and set `ADMIN_API_KEY`.
5. Run locally: `uvicorn app.main:app --reload` (SQLite is the development default).
6. API docs: `http://127.0.0.1:8000/docs`.

## Signing keys
Run `python scripts/generate_keys.py`. Store the private key only in Render environment secrets. Embed the public key in the Windows client. Never commit production keys.

## Deploy
Create a Neon PostgreSQL database, connect its URL to Render as `DATABASE_URL`, then set `ADMIN_API_KEY`, Ed25519 keys and SMTP credentials in Render. The Render start command applies Alembic migrations before starting the API.

## Issue a license
POST `/v1/admin/licenses` with header `X-Admin-API-Key` and body `{"email":"customer@example.com","expires_at":null}`. The serial is returned once; only its SHA-256 hash is stored.

## Production release gates
A live API still requires Neon and Render resources and working SMTP credentials. The Windows client also requires activation UI, a stable device fingerprint, Ed25519 signature verification and 14-day offline grace logic. Do not distribute a production build until those are implemented and tested.
