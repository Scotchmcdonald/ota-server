# ESP Fleet: ESP32 Fleet Management & OTA Server

Production-ready fleet command and OTA orchestration for ESP32 devices running ESP-IDF v5. ESP Fleet combines a FastAPI + SQLAlchemy backend with a Jinja2 + Tailwind CSS control surface, presented in a Flight Deck-style UI/UX, to provide secure onboarding, scoped fleet operations, and deterministic firmware rollout logic.

At runtime, devices identify themselves by MAC address and periodically call a single OTA decision endpoint. The server stores device identity, ownership scope, profile compatibility, and firmware release metadata in SQLite (WAL mode), then returns either a firmware binary (`200 OK`) or a no-update response (`204 No Content`) based on a strict cascading resolver.

For operators, the dashboard provides one place to claim hardware, upload profile-bound firmware binaries, assign deployment targets, and monitor check-ins/battery telemetry. For security, access is gated by Google OAuth 2.0 plus allowlisted emails/domains, with role-aware controls and optional admin API root tokens for machine-to-machine operations.

---

## 1. Project Title & Overview

### What ESP Fleet Is
ESP Fleet is a web-hosted OTA command layer for ESP32 fleets. It is designed to keep endpoint devices generic and stateless from the fleet perspective: each unit is fundamentally identified by MAC address, then mapped to ownership scope and deployment intent on the server side.

### Technology Stack
- **Backend:** FastAPI, SQLAlchemy ORM, SQLite (WAL mode)
- **Frontend:** Jinja2 templates + Tailwind CSS dashboard
- **Device Runtime Target:** ESP-IDF v5 firmware (ESP32 family)
- **Packaging/Deploy:** Docker + Docker Compose

### Why It Matters
This architecture enables controlled, auditable OTA release behavior with minimal firmware-side complexity. Instead of hardcoding update channels into embedded firmware, the control plane resolves update intent dynamically based on fleet metadata and role-governed admin actions.

---

## 2. Core Architecture: Cascading Resolution

ESP Fleet resolves OTA payloads using a deterministic two-tier priority model after device authentication and telemetry update.

### Device Identity Model
- Devices first appear as unknown check-ins keyed by `X-Device-MAC`.
- Unknown MACs are auto-registered as unclaimed and surfaced in the dashboard for claim workflow.
- Claimed devices receive a per-device secret and optional hardware profile assignment.

### Resolution Order
1. **Developer Override (Per Device):**
   - If `device.firmware_override_id` is set, that release is selected first.
2. **Fleet/Scope Target (Application Group):**
   - If no override is present, the device's `application_group.target_release_id` is used.

If neither source resolves to a release, the server returns **`204 No Content`**.

### Safety Gates Before Serving a Binary
Even when a target release is found, ESP Fleet blocks dispatch unless all checks pass:
- Firmware profile must match device profile (cross-profile protection).
- Target version must be semantically newer than device-reported version.
- Binary file must exist on disk.

If any check fails, response is **`204 No Content`**.

---

## 3. Features

### Flight Deck-Style UI Capabilities
- **Onboarding / Claiming Nodes**
  - Auto-discovers unknown MACs via `/check-update` registration behavior.
  - Claim flow binds device to scope (personal or team), assigns profile, and issues device secret.
- **Deploying Payloads**
  - Upload `.bin` firmware releases bound to a specific device profile.
  - Assign a release as the target for an application group.
  - Apply per-device firmware override for targeted testing/hotfixes.
- **Fleet Visibility & Telemetry**
  - Fleet tab shows device identity, reported firmware, check-in activity, and battery value (when parseable).
  - Supports unclaim and override actions from fleet operations view.

### Security & Access Control
- **Google OAuth 2.0 login flow** with callback handling and session cookie middleware.
- **Role-based access**
  - `Admin`: full management (teams, access allowlists, uploads, deployments, key management).
  - `User` (operator-style scoped access): constrained by personal/team scope ownership.
- **Allowlist controls**
  - Explicit allowed emails
  - Domain wildcard rules (e.g., `@example.com`)
- **Admin API Root Tokens**
  - One-time-display generated admin API keys (stored as SHA-256 hashes).
  - Used for machine-to-machine admin operations where applicable.

---

## 4. Prerequisites & Environment Variables

### Prerequisites
- Docker Engine (Desktop/OrbStack-compatible)
- Docker Compose v2+

### Required Environment Variables
The application uses the following environment variables:

```dotenv
# Google OAuth credentials
GOOGLE_CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET

# Must exactly match the Authorized Redirect URI configured in Google Cloud Console
# Example (reverse proxy): https://ota.yourdomain.com/auth
GOOGLE_OAUTH_REDIRECT_URI=https://YOUR_DOMAIN/auth

# Bootstrap allowlist seed (comma-separated emails), used at startup
ADMIN_EMAILS=you@example.com,admin@example.com

# Session signing key for Starlette session middleware
SESSION_SECRET_KEY=GENERATE_A_LONG_RANDOM_SECRET
```

### Redirect URI Strictness (Important)
Google OAuth redirect URIs are exact-match only. Behind a reverse proxy, **scheme, host, and path must match exactly** between:
- `GOOGLE_OAUTH_REDIRECT_URI`
- Google Cloud Console Authorized Redirect URI

Common mismatch causes:
- `http` vs `https`
- missing `/auth` path
- wrong external domain when proxy terminates TLS

### Database URL Note
The current code stores SQLite at `/app/data/ota.db` and does **not** expose a configurable `DATABASE_URL` environment variable.

---

## 5. Local Setup & Deployment

### 1) Configure environment values
Current `docker-compose.yml` includes placeholder inline values under `environment:`. Replace those values before first run.

### 2) Build and start
```bash
cd esp32-ota-server
docker compose build
docker compose up -d
```

### 3) Verify service
```bash
docker compose ps
docker compose logs -f ota-server
```

### 4) Access dashboard
- Open `http://localhost:8321/dashboard`
- You will be redirected to Google OAuth login if not authenticated.

### First Login / Bootstrapping Access
At startup, `ADMIN_EMAILS` is seeded into the allowlist table if entries do not already exist.

Recommended first-run path:
- Put your Google account email in `ADMIN_EMAILS`
- Start the stack
- Log in via Google
- Manage additional emails/domains from the **Access** tab

If you are locked out, add an allowed email directly in the containerized SQLite DB:

```bash
docker compose exec ota-server python -c "import sqlite3, datetime; db=sqlite3.connect('/app/data/ota.db'); db.execute('INSERT OR IGNORE INTO allowed_emails (email, note, created_at) VALUES (?, ?, ?)', ('you@example.com','manual bootstrap', datetime.datetime.utcnow().isoformat())); db.commit(); print('ok')"
```

Then retry login.

---

## 6. Embedded Firmware Integration (ESP-IDF)

ESP Fleet is consumed by ESP-IDF firmware through periodic HTTPS POST checks (see `fleet_ota.c`).

### Request Shape
In the current firmware implementation, the OTA task sets:
- `X-Device-MAC`
- `X-Device-Version`
- `X-Device-Battery`

It also configures:
- HTTPS certificate bundle via `esp_crt_bundle_attach`
- OTA polling loop in a dedicated FreeRTOS task (15-minute interval)

### Response Handling on Device
- **`200 OK`**: device treats response as firmware payload and performs OTA download/install.
- **`204/304`**: device treats response as up-to-date/no update and retries later.

### Integration Contract Note
Current backend `/check-update` logic expects headers:
- `X-Device-MAC`
- `X-Device-SECRET`
- `X-Firmware-Version`
- optional `X-Device-Battery`

To keep OTA checks fully aligned, firmware and server header contracts should be normalized in the same release train.

---

## API & Runtime Notes

### OTA Endpoint
- **Method:** `POST`
- **Path:** `/check-update`
- **Outcomes:**
  - `200` + binary stream + `X-Firmware-Version` header
  - `202` for unknown/unclaimed device registration states
  - `204` for no eligible update
  - `403` for secret mismatch

### Data Persistence
- Firmware files and SQLite database are persisted via Docker volume mapping:
  - host: `./data`
  - container: `/app/data`

---

## Repository Context

This README documents the production behavior reflected in the current implementation of:
- `main.py`
- `models.py`
- `templates/dashboard.html`
- `docker-compose.yml`
- `components/fleet_manager/fleet_ota.c`
