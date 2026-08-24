# ESP Fleet: ESP32 Fleet Management & OTA Server

Fleet command and OTA orchestration for ESP32 devices running ESP-IDF v5. ESP Fleet combines a FastAPI + SQLAlchemy backend with a Jinja2 + Tailwind CSS control surface to provide secure onboarding, flexible tag-based fleet targeting, and safe firmware rollout with rollout-gap auditing.

At runtime, devices identify themselves by MAC address and periodically call a single OTA decision endpoint. The server stores device identity, ownership scope, tags, and firmware release metadata in SQLite (WAL mode), then returns either a firmware binary (`200 OK`) or a no-update response (`204 No Content`) based on a deterministic resolver.

For operators, the dashboard provides one place to claim hardware, upload firmware (versioned or one-shot), assign devices to fleets, tag devices and releases for flexible targeting, preview a deployment's rollout gaps before committing, and monitor check-ins/battery telemetry. Access is gated by Google OAuth 2.0 plus allowlisted emails/domains, with role-aware controls and admin API tokens for machine-to-machine operations (e.g. CI firmware uploads).

---

## 1. Architecture

### Technology Stack
- **Backend:** FastAPI, SQLAlchemy ORM, SQLite (WAL mode) — organized as a small `routers/` package (`ota`, `firmware`, `fleet`, `devices`, `pages`, `auth`, `admin`) plus shared `database.py` / `config.py` / `schemas.py` / `deps.py` / `utils.py` / `bootstrap.py` modules, rather than one monolithic file.
- **Frontend:** Jinja2 templates + Tailwind CSS dashboard.
- **Device Runtime Target:** ESP-IDF v5 firmware (ESP32 family).
- **Packaging/Deploy:** Docker + Docker Compose.

### Fleet + Tags Model
Devices are managed either as independent **Singles** or grouped into a **Fleet** for bulk management. Both Devices and Fleets carry an arbitrary set of **Tags** (hardware, firmware-compatibility, custom, etc). Firmware releases also carry tags describing what they require.

Firmware comes in two tiers:
- **VersionedRelease** — SemVer'd, tagged, goes through a Staging → Approved/Rejected lifecycle before it's eligible for normal resolution.
- **OneShotRelease** — a raw binary for rapid prototyping, no SemVer or tags, assignable directly to a device or fleet.

### OTA Resolution (`POST /check-update`)
On every device check-in, the server resolves an update in priority order:
1. **Device-level One-Shot pin** — if the device has a `target_oneshot_release_id` set, that binary is served directly.
2. **Device-level target** — if the device has its own `target_firmware_name` set (LATEST or FIXED mode), that takes priority over its fleet.
3. **Fleet-level target** — otherwise, if the device belongs to a Fleet, the fleet's One-Shot pin or LATEST/FIXED firmware target is used.
4. **Fallback** — the device's self-reported firmware name, LATEST mode, no tag requirement.

**Subset tag matching** gates every resolution: a release's tags must all be present on the target device (a device may carry additional tags beyond what the release requires — that's tracked as "drift," not a block). A release with a required tag the device lacks is never served. Compute-module (hardware architecture) matching is a separate hard requirement, checked independently of tags.

### Rollout Gap Analysis
Before committing a Fleet deployment, `POST /api/deploy/preview` computes, per device: exact tag match, drift (extra tags), blocked (missing a required tag), and any compute modules present in the fleet with no uploaded binary at all ("missing hardware"). If any gap is flagged, the operator must explicitly acknowledge it (`acknowledge_gaps=true`) before `POST /api/fleet/{id}/deploy` will commit.

---

## 2. Device Identity & Onboarding

- Devices first appear as unknown check-ins keyed by `X-Device-MAC`, auto-registered as unclaimed and surfaced in the dashboard's Onboarding tab.
- An admin claims a device, assigning it a scope (personal or team) and generating its per-device secret.
- On every check-in the device sends `X-Device-MAC`, `X-Device-Secret`, `X-Firmware-Name`, `X-Firmware-Version`, `X-Compute-Module`, and optionally `X-Device-Battery`.

---

## 3. Security & Access Control

- Google OAuth 2.0 login flow with callback handling and session cookie middleware.
- **Role-based access** — `Admin` (full management) vs `User` (scoped to personal/team ownership).
- **Allowlist controls** — explicit allowed emails, plus domain wildcard rules (e.g. `@example.com`).
- **Admin API tokens** — for machine-to-machine firmware uploads (see `X-Admin-Key` header on `/admin/upload-firmware`, `/admin/upload-oneshot`).

---

## 4. Running It

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
# fill in GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_OAUTH_REDIRECT_URI /
# ADMIN_EMAILS / SESSION_SECRET_KEY in docker-compose.override.yml (gitignored,
# never commit real secrets to docker-compose.yml itself)
docker compose up -d --build
```

The server listens on the port mapped in `docker-compose.yml` (default `8321:8000`), backed by a SQLite database and firmware binary storage under `./data`, bind-mounted into the container.
