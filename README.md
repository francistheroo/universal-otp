# Universal OTP Service

A small central API for sending and verifying email one-time passwords (OTPs), built with FastAPI and Gmail SMTP.

## Features

- Six-digit OTPs with a five-minute expiry
- OTPs stored as keyed HMAC digests, not plaintext
- Single-use verification and a five-attempt limit
- Per-email send/verify request limits and a 60-second resend cooldown
- Bearer API-key authentication
- PostgreSQL support and a local SQLite development fallback
- Render deployment blueprint and health endpoint

## API

All OTP endpoints require this header:

```http
Authorization: Bearer YOUR_API_SECRET_KEY
Content-Type: application/json
```

### Send an OTP

`POST /send-otp`

```json
{"email":"person@example.com"}
```

### Verify an OTP

`POST /verify-otp`

```json
{"email":"person@example.com","otp":"123456"}
```

### Health

`GET /health`

Interactive API documentation is available at `/docs`.

## Run locally

1. Use Python 3.11 or newer.
2. Create and activate a virtual environment.
3. Install dependencies: `pip install -r requirements.txt`.
4. Set the environment variables shown in `.env.example`.
5. Start: `uvicorn app.main:app --reload`.

## Deploy on Render

1. Connect this repository to Render and create a Web Service using the included `render.yaml`.
2. Add a managed PostgreSQL database and set `DATABASE_URL` to its internal connection string.
3. Set `SMTP_USERNAME` to the Gmail address and `SMTP_APP_PASSWORD` to a Google App Password. Do not use your normal Gmail password.
4. Set `SMTP_FROM` to the same authorized sender address.
5. Keep `API_SECRET_KEY` and `OTP_PEPPER` private. Render can generate them through the blueprint.

## Important production notes

- Render's free web services can sleep when idle, and free instances are not an always-on guarantee.
- Gmail has sending limits and may block or throttle automated mail. This is not an unlimited bulk-email service.
- The included rate limits are process-local. Before running multiple instances or handling public high-volume traffic, use a shared rate limiter (such as Redis), add monitoring, abuse controls, and verify email ownership for client applications.
- Use PostgreSQL in deployment. SQLite on an ephemeral web-service filesystem is not durable.
- Never commit credentials, app passwords, database URLs, or production secrets.
