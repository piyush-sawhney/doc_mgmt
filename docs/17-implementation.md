# 17 — Implementation Status

> **In plain words:** The documents in this folder are the plan. This page is the scoreboard: what
> has actually been built, what has been tested, and where the code is still thinner than the
> design. If the two ever disagree, this page is how we notice before an operator does.
>
> **Read this if:** you are picking up the code, reviewing a slice, or deciding what to build next.

---

## 1. How to read this page

| Status | Meaning |
|---|---|
| **Done** | Implemented, reachable from the CLI or API, and covered by tests |
| **Partial** | Works for the documented path, but a named gap remains |
| **Not started** | No code; the design is still the only source |
| **Deferred** | Deliberately out of this build, with the reason recorded |

The three contracts still win: [vault format](03-vault-format.md),
[data model](04-data-model.md), and [API](07-api.md). This page does not relax them. When a slice
cannot meet a contract yet, it is listed in §6 with its resolution.

**Keeping it honest:** every implementation slice updates three things — the status table in §2,
the component row in §4, and the deviation list in §6. A slice that changes bytes on disk or
database columns also updates the contract document and adds a test.

Last updated: **2026-10-28**, application version **0.1.0**.

## 2. Snapshot

| Area | State | Evidence |
|---|---|---|
| Design documents | **Done** | `docs/00`–`16` plus glossary and two READMEs |
| Backend foundation | **Partial** | Vault creation, crypto, lock, audit, health, CLI |
| Database schema and migrations | **Not started** | No models, no Alembic revision, no seed catalogue |
| Database provisioning and dumps | **Not started** | `init` creates the vault and TLS only |
| Authentication, sessions, ACL enforcement | **Not started** | No login endpoint, no permission gate |
| Entities, documents, versions, upload/download | **Not started** | No tables and no routes |
| Render worker and previews | **Not started** | No `app/render/` or `worker/` |
| Print composition | **Not started** | No `app/print/` |
| Frontend | **Not started** | No `frontend/`; Node and npm are not installed on this dev host |
| Packaging and Windows install | **Not started** | No PyInstaller spec, MSI, or service unit |
| Unit tests | **Done for current code** | **67 passed** on 2026-10-28 |
| Integration tests | **Not started** | The marker and empty package exist; there are no PostgreSQL fixtures |
| Lint and type checks | **Passing** | `ruff check backend`, `mypy app` (run from `backend/`) |

The current build is a **vertical slice of the vault, not of the product**. It can create a vault,
protect it with a passphrase, take the single-writer lock, verify the audit chain, and answer
liveness and readiness. It cannot yet store a document.

## 3. What runs today

### 3.1 Setup

```bash
python3.14 -m venv .venv
uv pip install --python .venv/bin/python -e "backend[dev]"
cp config/dev.toml.example config/dev.toml
```

Edit `config/dev.toml` for the local paths. The file holds no secrets. The development vault is
disposable; production setup is [15](15-production-setup.md).

### 3.2 First vault

```bash
.venv/bin/docvault --config config/dev.toml \
  init --vault /absolute/path/to/var/vault --display-name "Development vault"
```

The command prompts twice for the passphrase, applies the policy in [05 §8](05-crypto.md),
creates the folder layout, writes `manifest.json` and `keys/kek.wrapped`, appends
`vault.created` to the audit log, generates the development CA and server certificate beside the
vault, and rewrites `[vault].root` in the configuration file.

It then prints the vault ID, key fingerprint, TLS directory, and certificate fingerprints. It
also prints:

```text
database: not provisioned by this build (see docs/17-implementation.md)
```

That line is the honest boundary of this slice. Database provisioning is §7 slice S2.

### 3.3 Inspection and unlock

```bash
.venv/bin/docvault --config config/dev.toml status
.venv/bin/docvault --config config/dev.toml doctor
.venv/bin/docvault --config config/dev.toml unlock
.venv/bin/docvault --config config/dev.toml serve
```

| Command | Current behaviour |
|---|---|
| `status` | Reads the manifest without unlocking, reports lock state, blob and audit counts, TLS fingerprints, and verifies the audit chain |
| `doctor` | Checks configuration, manifest, filesystem, key file, audit chain, PostgreSQL 18 client tools, and TLS material. The database connection check intentionally reports **FAIL** until S2 |
| `unlock` | Takes the writer lock, unwraps the VMK, verifies the manifest, appends `vault.unlock.allow`, then releases the lock. It proves the passphrase; it cannot unlock a service in another process yet |
| `lock` | Prints that live unlock/lock IPC is pending and exits **1** |
| `serve` | Opens the vault, prompts for the passphrase if locked, requires the TLS certificate pair, then runs the HTTPS API |

`serve` refuses to start without TLS on purpose. A plaintext listener is never a supported mode.

### 3.4 API

Only two routes exist:

| Route | Behaviour |
|---|---|
| `GET /healthz` | Always `200 {"status":"ok"}` while the process is alive |
| `GET /readyz` | `200` only when the vault is open and unlocked; otherwise a `503` RFC 9457 problem document |

Everything else in [07](07-api.md) is design, not code.

### 3.5 Checks

```bash
cd backend
../.venv/bin/pytest tests/unit -q
../.venv/bin/mypy app

cd ..
.venv/bin/ruff check backend
```

`mypy` must run from `backend/` so `pyproject.toml` supplies the strict configuration. The
`pytest` run uses temporary directories only; no test touches a real vault or a database.

## 4. Component status

### 4.1 Core

| Module | Design reference | State | Notes |
|---|---|---|---|
| `app/core/config.py` | [14 §4.4](14-development.md), [15 §11](15-production-setup.md) | **Done** | Typed TOML, unknown keys rejected, absolute paths, loopback-only DSN by default, comment-preserving root rewrite |
| `app/core/errors.py` | [07 §3](07-api.md) | **Partial** | Catalog and RFC 9457 documents; new codes are added as each slice introduces them |
| `app/core/logging.py` | [02 §9](02-architecture.md) | **Done** | JSON logs, request-ID context, redaction of sensitive fields |
| `app/core/time.py` | [02 §9](02-architecture.md) | **Done** | UTC helpers and millisecond/second rendering |
| `app/core/http.py` | [07 §3](07-api.md), [02 §9](02-architecture.md) | **Done** | Request-ID middleware and problem handlers, including validation errors |
| `app/core/tls.py` | [15 §2](15-production-setup.md), [08 §2.1](08-ops.md) | **Partial** | Private CA and server certificate; no rotation command and no client-certificate mode |

### 4.2 Cryptography

| Module | Design reference | State | Notes |
|---|---|---|---|
| `app/crypto/canonical.py` | [03 §3](03-vault-format.md) | **Done** | Sorted, compact UTF-8 JSON; base64url helpers |
| `app/crypto/keys.py` | [05 §2–6](05-crypto.md), [03 §4–6](03-vault-format.md) | **Partial** | HKDF sub-keys, Argon2id VMK wrap, AES-256-GCM, column encryption, blind indexes, blob addresses. `rotate-passphrase` and `rotate-vmk` are not built |
| `app/vault/blobs.py` | [03 §5](03-vault-format.md) | **Partial** | DVC1 memory and streaming writer, authenticated reader, header parsing, padding. No `verify` or `salvage` command yet |
| `app/crypto/passphrase.py` | [05 §8](05-crypto.md) | **Done** | Minimum length, local common-phrase list, `zxcvbn` score ≥ 3 |

### 4.3 Vault

| Module | Design reference | State | Notes |
|---|---|---|---|
| `app/vault/layout.py` | [03 §2](03-vault-format.md), [03 §7](03-vault-format.md) | **Partial** | Layout, permissions, atomic writes, symlink/network/rename/fsync/casing probes. The Windows filesystem branch is code-reviewed, not executed |
| `app/vault/manifest.py` | [03 §3](03-vault-format.md) | **Partial** | Build, sign, verify, load, schema-version bump, unknown-field preservation. No operator-facing edit command |
| `app/vault/audit.py` | [03 §10](03-vault-format.md) | **Partial** | Monthly JSONL append and full-chain verification. No anchor file generation and no database mirror |
| `app/vault/lock.py` | [03 §11](03-vault-format.md) | **Done** | Exclusive create, 5-second heartbeat, 30-second staleness, audited forced takeover |
| `app/vault/init.py` | [09 §1](09-flows.md) | **Partial** | Vault identity and key wrapping only; TLS is orchestrated by the CLI. Database, schema, seed, and first dump are absent |
| `app/vault/session.py` | [09 §1](09-flows.md), [05 §9](05-crypto.md) | **Partial** | Open, unlock, in-memory lock, close, status, unlock back-off. No automatic unlock, no idle lock, no live IPC |
| `app/vault/inspect.py` | [08 §1](08-ops.md) | **Done** | Read-only manifest, lock, blob, audit, dump-pointer, and TLS inspection |

### 4.4 API, CLI, and process

| Module | Design reference | State | Notes |
|---|---|---|---|
| `app/api/health.py` | [07 §1](07-api.md) | **Done** | `/healthz` and `/readyz` |
| `app/main.py` | [02 §8](02-architecture.md) | **Partial** | App factory and lifespan; only the health router is mounted |
| `app/cli.py` | [08 §1](08-ops.md) | **Partial** | `init`, `status`, `doctor`, `unlock`, `lock`, `serve`. Backup, restore, verify, migrate, rotate, salvage, and user commands are absent |
| `app/db/` | [04](04-data-model.md) | **Not started** | No models, repositories, migrations, or seed catalogue |
| `app/services/` | [06](06-rbac-acl.md) | **Not started** | The single permission gate does not exist yet |
| `app/render/`, `app/print/`, `app/jobs/` | [11](11-frontend.md), [12](12-printing.md), [08 §1](08-ops.md) | **Not started** | — |
| `worker/` | [02 §8](02-architecture.md) | **Not started** | The package name is reserved in `pyproject.toml`; no entry point exists |
| `frontend/` | [11](11-frontend.md) | **Not started** | Node and npm are absent on this development host |

## 5. Test evidence

### 5.1 Current suite

| File | What it proves |
|---|---|
| `test_crypto_keys.py` | Sub-key separation, a locked fingerprint vector, DVK1 round trip, wrong passphrase, tampered tag, absurd Argon2 cost, column AAD binding, blind-index normalisation, salt-scoped addresses |
| `test_blobs.py` | DVC1 header and padding, empty plaintext, tampering, wrong key, address mismatch, unknown flags and magic, streaming writer addresses, short and long sources |
| `test_manifest.py` | Canonical JSON, signing, unknown-field preservation, tamper detection, fan-out rejection, wrong fingerprint, readable bytes round trip |
| `test_audit.py` | Zero hash, cross-month chaining, middle-entry tampering, the documented newest-line truncation limit, and refusal to append after a partial line |
| `test_lock.py` | Second writer refused, release, heartbeat record, stale detection, forced takeover, forced-takeover audit |
| `test_layout.py` | Layout creation, atomic write, private modes, symlink rejection, network filesystem rejection, relative root rejection, fan-out paths, idempotence |
| `test_config.py` | Development shape, unknown keys, remote DSN refusal, relative root refusal, missing file, comment-preserving root rewrite |
| `test_init.py` | Vault identity, second-init refusal, weak passphrase refusal, unlock, wrong-passphrase audit, status without unlock, lock release |
| `test_http.py` | `/healthz`, locked `/readyz`, ready `/readyz`, request-ID echo, problem documents, unknown route |

The suite is deliberately unit-level. It proves the crypto and filesystem contracts that are
cheapest to get wrong, not that the product works end to end.

### 5.2 Manually verified on 2026-10-28

A fresh development vault was created under `/tmp`, then inspected:

- `init` created the layout, manifest, 96-byte key file, audit entry, CA, and server certificate.
- `status` reported one audit entry, `lock: free`, `blob_count: 0`, and `audit_chain: ok`.
- `doctor` reported every check **PASS** except the database connection, which is expected until
  S2.
- `unlock` accepted the passphrase, verified the manifest, and released the lock on exit.

### 5.3 Not yet tested

| Gap | Consequence |
|---|---|
| Windows filesystem and path handling | The production target is unexercised |
| Concurrent processes and heartbeat failure | Stale-lock takeover is tested by writing a file, not by killing a live writer |
| Large streamed uploads and disk-full behaviour | The streaming writer is tested with 9 KB, not a 100 MB document |
| Crash injection during `init`, blob write, or dump | Cleanup paths are reasoned about, not fault-injected |
| TLS handshake with a real client | Certificates are generated and fingerprinted, not used by a browser |
| Any PostgreSQL behaviour | No schema or query exists |
| Frontend | No code |

## 6. Deviations and open gaps

Each item names what the design expects, what the code does, and how it closes. Temporary gaps are
allowed only while this table says so; a gap without a slice is a defect.

| ID | Design expects | Current build | Resolution |
|---|---|---|---|
| IMP-01 | `docvault init` provisions the role, database, schema, seed catalogue, and first dump ([08 §2](08-ops.md), [09 §1](09-flows.md)) | Creates the vault and TLS only; prints that the database is not provisioned | **S2** |
| IMP-02 | A running service can be unlocked and locked through IPC ([08 §7](08-ops.md)) | `unlock` proves the passphrase in a short-lived process; `lock` exits **1** with a pending-IPC message | **S3** |
| IMP-03 | Automatic unlock uses DPAPI/keyring when opted in ([15 §6.3](15-production-setup.md)) | `vault.auto_unlock` is parsed, but `serve` refuses with `CONFIG_INVALID` | **S2/S3** |
| IMP-04 | Schema, Alembic migrations, seeded document types, constraints, triggers, and indexes ([04](04-data-model.md)) | Nothing exists | **S1** |
| IMP-05 | Encrypted `DVD1` dumps, `LATEST`, backup, restore, and pre-migration dumps ([03 §9](03-vault-format.md), [08 §3–4](08-ops.md)) | No dump format implementation and no commands | **S2** |
| IMP-06 | Database credential stored in DPAPI or the OS keyring, never in TOML ([02 §6.3](02-architecture.md)) | No credential storage | **S2** |
| IMP-07 | `doctor` checks the live database and its version ([08 §1](08-ops.md)) | Reports **FAIL** unconditionally with the DSN, so the command exits **1** until S2 | **S2** |
| IMP-08 | Auth, sessions, CSRF, lockout, roles, and the single ACL gate ([06](06-rbac-acl.md), [07 §2](07-api.md)) | No sessions and no permission code | **S3** |
| IMP-09 | Entities, persons, identifiers, documents, versions, uploads, downloads, and audit database writes ([07 §4–5](07-api.md)) | No routes beyond health | **S4** |
| IMP-10 | Office intake converts once at ingest to a derived PDF; previews are encrypted renditions ([10 ADR-038](10-decisions.md), [11](11-frontend.md)) | No render worker; `office.convert_exe` is parsed but unused | **S5** |
| IMP-11 | Print composition produces one PDF in memory, with no stored artifact ([12](12-printing.md)) | No composer | **S6** |
| IMP-12 | React frontend served from the same origin ([11](11-frontend.md)) | No frontend; Node and npm are missing on this machine | **S7** |
| IMP-13 | Windows production installation, service, MSI, and filesystem behaviour ([15](15-production-setup.md)) | Only Linux development paths have been executed | **S8** |
| IMP-14 | Python `3.14.10` ([02 §6.1](02-architecture.md)) | Local interpreter is `3.14.4`; no feature depends on the patch level, but release builds must use the pin | **S8** |
| IMP-15 | `doctor` is a read-only inspection | Its filesystem probe writes short-lived probe files under `tmp/`. It never creates missing vault folders or modifies content, but the filesystem must be writable | Documented behaviour; no action unless a read-only doctor is required |
| IMP-16 | The design is the base for code | `backend/app/crypto/blobs.py` was moved to `backend/app/vault/blobs.py` to match the layout in [02 §8](02-architecture.md) | Closed 2026-10-28 |

### 6.1 Known limits carried from the design

These are not implementation defects. They are recorded so a reviewer does not mistake them for
one.

| Limit | Reference |
|---|---|
| Truncating the newest audit line leaves a chain that still verifies | [03 §10](03-vault-format.md) |
| No deduplication: the same bytes uploaded twice produce two blobs and two versions | [10 ADR-012](10-decisions.md) |
| No crypto-shredding; purge is best effort | [10 ADR-011](10-decisions.md) |
| Permissions are application-level, not cryptographic | [05 §7](05-crypto.md), [06 §11](06-rbac-acl.md) |
| The browser receives plaintext for documents the user may read | [11 §15](11-frontend.md) |

## 7. Next slices

Slices are ordered so that each one can be tested before the next depends on it. A slice is done
when its tests pass, the contracts still hold, and this page is updated.

### S1 — Database foundation

**Build:** SQLAlchemy 2.0 models for every table in [04](04-data-model.md), Alembic configuration
and the first migration, documented enums and constraints, partial indexes, updated-at and
immutability triggers, and the seeded two-level `doc_types` catalogue (eight categories and the
types listed in [13 §4](13-classification.md)). Add a PostgreSQL 18 fixture that creates a
temporary database on the throwaway cluster.

**Exit criteria:** migration upgrades an empty database and downgrades cleanly; constraints reject
bad rows; the seed is idempotent; integration tests run against real PostgreSQL, never SQLite.

### S2 — Provisioning, credentials, and dumps

**Build:** `init` creates the `docvault_app` role and `docvault` database when given an admin
connection, stores the credential outside the vault, runs migrations, seeds the catalogue, and
writes the first encrypted `DVD1` dump plus `LATEST`. Add `backup`, `restore`, and `dump-list`.
Wire the real database checks into `doctor` and the last-dump line into `status`.

**Exit criteria:** a fresh `init` produces a database the app can open; `doctor` passes on a
correct host; a dump restores into an empty cluster; a wrong passphrase or wrong vault ID refuses.

### S3 — Authentication, sessions, and the permission gate

**Build:** login, logout, session cookie, CSRF, lockout, password change, user administration, and
one ACL resolver implementing [06 §5](06-rbac-acl.md). Add audit database writes in the same
transaction as the change. Add live unlock/lock IPC or a documented single-process replacement.

**Exit criteria:** the [06 §10](06-rbac-acl.md) matrix passes; unauthorised requests return `404`
rather than `403` where the design requires it; every allow and deny is audited.

### S4 — Entities, documents, and versions

**Build:** entity and person CRUD, identifier blind indexes, document create/update/soft-delete,
version upload and download, blob write and read through `vault/blobs.py`, MIME sniffing, format
rejection (including TIFF), size limits, and idempotent retries.

**Exit criteria:** [09 §3–5](09-flows.md) and [09 §9–10](09-flows.md) work end to end; a document
is unreadable on disk; an unauthorised download fails without leaking existence.

### S5 — Previews and Office intake

**Build:** the separate render worker with no vault key and no network, encrypted rendition cache,
JPEG/PNG/PDF previews, one-time Office-to-PDF conversion at ingest, and cache eviction.

**Exit criteria:** hostile-input corpus is rejected; the worker cannot open the vault; Office
intake is refused with `415` when no converter is configured.

### S6 — Print composition

**Build:** the layout maths and composer from [12](12-printing.md), page ranges, grid cells, duplex,
presets, one audit event per job, and no stored print artifact.

**Exit criteria:** golden-page hashes for every grid; page count and sheet count match the design;
a `restricted` document without an explicit `print` grant returns `403 PRINT_RESTRICTED`.

### S7 — Frontend

**Build:** the screens in [11](11-frontend.md) on React 19, TypeScript, Vite, and TanStack Query,
served by FastAPI from the same origin. Implement the viewer, print queue, and accessible table
patterns before polish.

**Exit criteria:** the [07 §10](07-api.md) contract tests exist; keyboard-only filing and printing
work; no key material reaches the browser.

### S8 — Packaging and production proof

**Build:** PyInstaller spec, Windows service, MSI, Linux unit, backup and restore drill, and the
production certificate flow. Run the [15](15-production-setup.md) go-live checklist on real
hardware.

**Exit criteria:** a clean Windows host installs, unlocks, uploads, prints, backs up, and restores
without a developer present.

## 8. Decisions still affecting the build

No new implementation decision has been made. The defaults in [10 §4](10-decisions.md) stand:

| Question | Default used by this build |
|---|---|
| O-8 — Office intake on by default? | On only when a converter is configured |
| O-11 — Do reader and editor get `print` by default? | Yes |
| O-13 — Explicit `print` grant for `restricted` documents? | Yes, admin exempt |

If the product owner answers differently, the answer changes S5 and S6, not the vault or schema.

## 9. Change log

| Date | Change |
|---|---|
| 2026-10-28 | First implementation status page. Vault slice, 67 unit tests, lint and type gates recorded. `blobs.py` moved to `vault/` to match `02` §8. Configuration key names in `08` corrected to the nested form. |
