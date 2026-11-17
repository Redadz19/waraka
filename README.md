# WARAKA — Licensing Service

Canonical FastAPI licensing backend for the WARAKA Windows PDF application. This repository is the source of truth for the licensing API; the older implementation under `PDF-Splitter/license-server` uses a different contract and must not be deployed alongside this API.

## Included
- Administrator-protected license issuance and revocation
- License binding to serial number and email address
- Email OTP required for every new device activation (10-minute validity, 60-second resend interval, five attempts)
- OTP bound to the exact license, not merely to an email address
- HMAC-SHA256 OTP digests using a server-side secret
- Three active devices per license
- Device activation, online verification and deactivation
- Ed25519-signed activation payloads including the signed expiry timestamp (null means lifetime)
- One-time purchase / lifetime-license support without recurring subscription billing
- PostgreSQL/Neon support, Alembic migrations and Render blueprint

## Local setup
1. Use Python 3.12+.
2. Create and activate a virtual environment.
3. Install dependencies: `pip install -r requirements.txt`.
4. Copy `.env.example` to `.env`.
5. Set `ADMIN_API_KEY`, `OTP_SECRET` (at least 32 random characters), SMTP credentials and a signing key.
6. Run locally: `uvicorn app.main:app --reload` (SQLite is the development default).
7. API docs: `http://127.0.0.1:8000/docs`.

## Signing keys
Run `python scripts/generate_keys.py`. Store the private key only in Render environment secrets. Embed the public key in the Windows client. Never commit production keys.

## Activation flow
1. The client sends serial and email to `POST /v1/otp/request`.
2. The server checks the license and sends a six-digit code to the license email.
3. The client sends serial, email, code, device ID and device name to `POST /v1/license/activate`.
4. The server consumes the one-time code and returns the signed license payload.
5. The client verifies the Ed25519 signature locally, checks the signed `expires_at` value (null means a lifetime license), permits up to the configured offline grace period, and performs online rechecks at the configured interval.

Lifetime licenses are issued with `expires_at: null`; this means a single purchase with no recurring renewal. The three-device limit and online/offline security checks still apply.

Other client endpoints:
- `GET /v1/public-key`
- `POST /v1/license/verify`
- `POST /v1/license/deactivate`

## Issue a license
POST `/v1/admin/licenses` with header `X-Admin-API-Key` and body `{"email":"customer@example.com","expires_at":null}`. The serial is returned once; only its SHA-256 hash is stored.

## Deploy
Create a Neon PostgreSQL database, connect its URL to Render as `DATABASE_URL`, then configure `ADMIN_API_KEY`, `OTP_SECRET`, Ed25519 keys and SMTP credentials in Render. The Render start command applies Alembic migrations before starting the API.

## Production release gates
A live API still requires Neon and Render resources and working SMTP credentials. The Windows client still requires activation UI, a stable device fingerprint, embedded public-key signature verification and tested 14-day offline grace logic. Do not distribute a production build until these are implemented and tested.
