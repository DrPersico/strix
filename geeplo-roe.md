# Geeplo — Rules of Engagement & Focus for Strix

## Target

**Geeplo** — a multi-tenant Google Workspace governance platform.
- Backend: FastAPI + SQLAlchemy (async) + Alembic + Celery + PostgreSQL (with Row-Level Security) + Redis. ~84K LOC Python under `backend/`.
- Frontend: Next.js App Router + React + ShadCN/ui + TanStack Query + Zustand. ~153K LOC under `frontend/`.
- Multi-tenant: every tenant's data must be isolated by `tenant_id`. Postgres RLS is the backstop.

This is a **white-box source review**. The app is NOT running — do not attempt to boot it or hit live endpoints. Reason over the source.

## Rules of engagement (HARD)

- **Source-only.** Do not send any traffic to real Google APIs (`googleapis.com`, `admin.google.com`, etc.). Do not resolve or contact any Google Workspace domain.
- **No persistence / no backdoors.** Do not write shells, webshells, scheduled tasks, modified migrations, or persistent access into the repo.
- **No third-party exploitation.** Do not attack GitHub, PyPI, npm, Docker Hub, or any external service.
- **Stay inside the repo.** All PoCs are reasoning traces + minimal crafted requests against the FastAPI/Next.js code paths, not live network exploits.
- **No secret exfiltration.** If you find committed credentials, report them as findings — do not attempt to validate them against external services.

## What makes Geeplo risky (prioritize these)

A prior OWASP audit (`security-audit.md`, 24 Jun 2026) already found 7 critical / 19 high. Your job is to (a) find what they missed, (b) find regressions, (c) chain things they didn't. Treat the prior audit as a floor, not a ceiling.

### 1. Multi-tenant isolation — THE #1 risk
- How is `tenant_id` derived on each request? URL path param? JWT claim? Query/body field? Anywhere a **client-controlled** `tenant_id` is trusted is critical.
- Postgres RLS: is it actually enabled on every tenant-scoped table? Check `backend/app/rls_observability.py`, the alembic migrations, and whatever session middleware sets the tenant GUC (`SET app.tenant_id`). Is there a code path that opens a session **without** setting the GUC?
- Raw SQL / `.execute()` / `text()` that bypass ORM-level tenant filters.
- Cross-tenant IDOR: endpoints that take an object id (`/drives/{id}`, `/groups/{id}`, `/teams/{id}`, `/datashield/.../{id}`) — does the handler verify the object belongs to the caller's tenant before returning/mutating?
- Bulk operations / exports / analytics that might span tenants.
- Celery tasks: do they carry a `tenant_id` and re-set the GUC inside the worker?

### 2. Authentication & authorization
- Google OAuth callback (`backend/app/blueprints/auth/`): `state` validation, PKCE, open-redirect on `next`/`redirect`/`return_to` params, token leakage in logs/responses.
- JWT: full validation? signature (HS vs RS, correct secret/key), `exp`, `iss`, `aud`, algorithm confusion (HS256 with RSA public key). Weak/default JWT secret — is there a guard rejecting the default in non-dev?
- Refresh tokens (`backend/app/blueprints/auth/_refresh_store.py`): storage, rotation, revocation, replay.
- Cookies: `HttpOnly`, `Secure`, `SameSite`. CSRF protection on cookie-authenticated state-changing endpoints.
- Impersonation + superadmin flows (`admin`, `auth` blueprints): what guards `require_superadmin` / impersonation? Can a non-superadmin reach it? Is impersonation logged?
- Mock/dev leakage: `AUTH_MOCK_MODE`, `GOOGLE_MOCK_MODE`, "dev auth suppress". Any code path where mock auth bypass could be enabled in non-dev environments?
- Per-router auth matrix: for every blueprint router, are auth deps (`get_current_user`, `verify_tenant_path`, `require_internal_admin`, `require_superadmin`) applied at the **router** level vs per-endpoint vs not at all?

### 3. DataShield destructive operations
Prior audit flagged the whole blueprint as unauthenticated. Verify current state. Every endpoint that **revokes Drive permissions**, **triggers a sync**, **modifies trusted domains**, or **schedules cleanup** must require auth + admin + tenant-scoped.

### 4. Service-account key storage (SAM blueprint)
Are Google service-account private keys stored as plaintext JSON in Postgres? Check the model/column. If "encrypted", verify the key management (where's the encryption key? hardcoded? env? KMS?).

### 5. Injection
- **SQLi**: `text()`, `.execute()`, `exec_driver_sql`, f-string/concatenated SQL, dynamic `order_by`/column names from request params.
- **SSRF**: any server-side fetch where the URL is influenced by user input — webhook delivery, "import from URL", thumbnail/icon proxying, OAuth `next` fetch. The webhooks blueprint is a prime spot.
- **Command injection**: `subprocess`, `os.system`, `shell=True`, `Popen` in Celery tasks, seed/migration scripts under `backend/scripts/`.
- **Path traversal**: `open()`, `Path()`, `shutil`, `send_file` with client-controlled paths — Transfer Tool and DataShield file ops.
- **Deserialization**: `pickle`, `yaml.load` (unsafe loader), `marshal`, `dill`, `json`→eval-ish.
- **SSTI**: any Jinja2/mako/templating with user input? (FastAPI doesn't by default, but check notifications/announcements rendering.)

### 6. Secrets
- JWT-secret weak-default guard (`backend/app/config.py`, `backend/tests/test_config_jwt_guard.py`).
- OAuth client secret — read from env? logged anywhere?
- Hardcoded passwords/tokens in alembic migrations (prior audit found `Adevinta2025!` committed), seed scripts, CI workflows (`.github/workflows/`), Dockerfiles, helm `values.yaml`.
- Secrets echoed in error responses (RFC 7807 `detail`) or logs.

### 7. Frontend
- **XSS sinks**: `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `Function(`, user-controlled `href={` (esp. `javascript:` URLs), `target="_blank"` without `rel="noopener"`. Hot spots: rendering Drive file names, group/member display names, audit-log details, announcement/markdown content.
- **Token storage**: is the JWT/session in `localStorage`/`sessionStorage`/URL query (bad) or HttpOnly cookie (good)? Search `localStorage`, `sessionStorage`, `document.cookie`.
- **CSP / security headers**: `next.config.js` `headers()` or middleware setting CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy.
- **CORS** (backend): `CORSMiddleware` with `allow_origins=["*"]` AND `allow_credentials=True` is critical. Report the exact config.
- **SSRF in Next.js**: server components / route handlers / `getServerSideProps` doing `fetch()` with user-influenced URLs; `next/image` remote patterns; rewrites/redirects in `next.config.js`.

### 8. Infrastructure
- Dockerfiles (backend + frontend): running as root? `COPY . .` bringing `.env`? debug ports exposed?
- `docker-compose*.yml`: hardcoded passwords, Flower/Redis/Postgres bound to `0.0.0.0`, debug modes.
- `.github/workflows/`: `pull_request_target` misuse, actions pinned by tag not SHA, overly broad `permissions:`, secrets echoed.
- `helm/`: secrets in plaintext values, privileged containers, serviceAccount automount.

## Deliverable expectation

For every finding, produce:
- **ID + title + severity** (Critical / High / Medium / Low) + **OWASP 2021 category**.
- **`file:line`** for the vulnerable code.
- **Input → sink trace**: the exact path from an attacker-controllable input to the dangerous sink, with the intermediate calls.
- **Minimal PoC**: a concrete crafted HTTP request (method, path, headers, body) or a code snippet that demonstrates the issue. No live traffic.
- **Impact**: what an attacker gains.
- **Fix**: specific, actionable remediation.

Prefer a few high-confidence, fully-traced findings over many speculative ones. Chain findings when possible (e.g., mock-auth-leak → cross-tenant IDOR → mass permission revocation).

## Out of scope (do not spend time on)

- The `node_modules/`, `.next/`, `graphify-out/`, `test-results/`, `__pycache__/` directories.
- The `openspec/`, `docs/`, `.ai-playbook/`, `.serena/` documentation trees (unless they contain real secrets).
- Theoretical issues with no reachable input path.
- Anything that requires live Google API access to validate.
