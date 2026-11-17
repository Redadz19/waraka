# WARAKA — Licensing Service

Backend licensing service for the WARAKA Windows PDF application.

## Stack
- FastAPI + PostgreSQL (Neon)
- SQLAlchemy 2 + Alembic
- Email OTP verification
- Signed license responses (Ed25519)
- Device activation limit: 3 devices per license

## Local development
1. Copy `.env.example` to `.env` and fill the values.
2. Create a PostgreSQL database.
3. Install dependencies: `pip install -r requirements.txt`
4. Run migrations: `alembic upgrade head`
5. Start: `uvicorn app.main:app --reload`

## Deployment
The included `render.yaml` defines a Render web service. Configure the environment variables in Render and connect a Neon PostgreSQL database. Do not commit production secrets.

## Important
This repository contains the licensing backend only. Production deployment still requires a Neon database, Render service, SMTP credentials, and application-side integration in the Windows client.
