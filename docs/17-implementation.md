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

Last updated: **2026-10-29**, application version **0.1.0**.

## 2. Snapshot

| Area | State | Evidence |
|---|---|---|
| Design documents | **Done** | `docs/00`–`16` plus glossary and two READMEs |
| Backend foundation | **Partial** | Vault creation, crypto, audit, CLI fault drills, and live POSIX lock/unlock IPC; Windows IPC and production bootstrap proof remain |
| Database schema and migrations | **Done** | 24 models, Alembic head `7e4c2b9a1f30`, triggers D-1–D-16, and the seeded catalogue |
| Database provisioning and dumps | **Partial** | Provisioning, encrypted dumps, backup/restore, and a CLI `init`→`migrate`→`backup`→`dump-list` drill; CLI restore and Windows bootstrap proof remain |
| Authentication, sessions, ACL enforcement | **Partial** | Login/TOTP/session/password routes, admin user/group APIs, ACL resolver, entity/document enforcement, access audits, and the documented resolver matrix; the full route-level matrix remains |
| Entities, documents, versions, upload/download | **Partial** | Encrypted uploads/versions, purge, tags, links, doc-type CRUD, search, one-use range downloads, ACL filters, and structural PDF inspection |
| Render worker and previews | **Partial** | Isolated Linux worker, encrypted renditions/cache, recipes, tickets, Office intake, PDF validation, and a hostile-input corpus; non-Linux isolation and real LibreOffice conversion remain unverified |
| Print composition | **Done** | In-memory PDF jobs, authorization, persistence, audit, metadata, interrupted-job recovery, and the documented layout/no-upscale contract are covered; presets are built-in values, not a server resource |
| Frontend | **Not started** | No `frontend/`; Node and npm are not installed on this dev host |
| Packaging and Windows install | **Deferred** | Packaging and production Windows installation are outside this backend slice |
| Unit tests | **Passing for current worktree** | **204 passed** |
| Integration tests | **Passing for current worktree** | **97 passed** against PostgreSQL 18.6 |
| Lint and type checks | **Passing for current worktree** | `ruff check backend`, `mypy app` (run from `backend/`) |

The backend API and worker paths for authentication, ACLs, entities, documents, previews, Office
intake, print composition, audit reads, and vault status are implemented and covered by the
current suite. The backend is still a **partial product slice**: Windows production support, the
route-level ACL matrix, global `/search`, mutable `/settings`, the remaining operational commands
(`verify`, `rotate-*`, `salvage`), and a real LibreOffice conversion run remain open. The frontend
and packaging are intentionally outside this backend completion scope.

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

The command prints the PostgreSQL admin password prompt first, unless `--admin-dsn` supplies it.
It creates the `docvault_app` role and `docvault` database, writes `config/docvault-db.cred` with
mode `0600`, then prompts twice for the passphrase, applies the policy in
[05 §8](05-crypto.md), creates the folder layout, writes `manifest.json` and `keys/kek.wrapped`,
appends `vault.created` to the audit log, generates the development CA and server certificate
beside the vault, rewrites `[vault].root` in the configuration file, and then applies the
migrations and seeds the catalogue.

It prints the vault ID, key fingerprint, TLS directory, certificate fingerprints, and the schema
version with the seeded catalogue size.

`--no-database` stops after TLS and is for a host with no PostgreSQL. `--reuse-vault` re-creates
the role password and credential file for an existing vault and touches nothing else:

```bash
.venv/bin/docvault --config config/dev.toml \
  init --vault /absolute/path/to/var/vault --reuse-vault
```

The current implementation writes the first encrypted dump after migration and seeding.
`docvault migrate` writes a pre-migration dump when the database revision is behind. The dump
format and database backup/restore operations are in S2b; their CLI orchestration still needs
end-to-end validation.

After initialization, create the first administrator before opening the browser:

```bash
.venv/bin/docvault user create --config config/dev.toml \
  --username admin --role admin
```

The command prints a temporary password, which must be changed at first sign-in. It refuses to
run after the first account exists.

### 3.3 Inspection and unlock

```bash
.venv/bin/docvault --config config/dev.toml status
.venv/bin/docvault --config config/dev.toml doctor
.venv/bin/docvault --config config/dev.toml unlock
.venv/bin/docvault --config config/dev.toml migrate
.venv/bin/docvault --config config/dev.toml serve
```

| Command | Current behaviour |
|---|---|
| `status` | Reads the manifest without unlocking, reports lock state, blob and audit counts, the latest dump pointer, TLS fingerprints, verifies the audit chain, and reports whether the database credential exists |
| `doctor` | Checks configuration, manifest, filesystem, key file, audit chain, PostgreSQL 18 client tools, TLS material, the credential file, the live server version, and — when a terminal is available for the passphrase — the database `vault_id` and schema version |
| `unlock` | Sends an unlock request to a running service over the private local control socket; if no service is available, it takes the writer lock, verifies the passphrase, and releases it |
| `migrate` | Takes the writer lock, unlocks, writes a pre-migration dump if a migration is pending, applies Alembic revisions, seeds the catalogue, stamps `vault_id` and `schema_version` into `settings`, and audits `database.migrate`. Safe to re-run; `--force-lock` takes over a stale lock |
| `backup` | Writes an encrypted database dump and updates `LATEST` after the dump is durable |
| `restore` | Decrypts and restores the latest or a named dump, then checks the database identity |
| `dump-list` | Prints a dump table of contents without restoring it |
| `user create` | Creates the first administrator account and prints a temporary password that must be changed on first sign-in |
| `lock` | Sends a lock request to the running service; the service revokes sessions and drops its in-memory vault keys |
| `serve` | Opens and unlocks the vault, requires the TLS certificate pair, verifies the database identity, recovers interrupted print jobs, starts local control IPC, then runs the HTTPS API |

`serve` refuses to start without TLS on purpose. A plaintext listener is never a supported mode.
It also refuses to start against a database belonging to another vault or a newer schema.

### 3.4 API

| Route | Behaviour |
|---|---|
| `GET /healthz` | Always `200 {"status":"ok"}` while the process is alive |
| `GET /readyz` | `200` only when the vault is open and unlocked; otherwise a `503` RFC 9457 problem document |
| `/api/v1/auth/*` | Login, TOTP, logout, session, password, and CSRF-protected account actions |
| `/api/v1/users/*`, `/api/v1/groups/*` | Administrator-only account and group management |
| `/api/v1/documents/{id}/acl`, `/api/v1/entities/{id}/acl` | ACL management; entity ACL changes are admin-only |
| `/api/v1/entities/*`, `/api/v1/identifiers/*` | ACL-checked entity/person/identifier routes; identifier values are masked except for audited reveal |
| `/api/v1/doc-types`, `/api/v1/tags` | Authenticated taxonomy reads and admin doc-type CRUD; tag CRUD |
| `/api/v1/documents` | Encrypted PDF/JPEG/PNG and Office uploads, versioning, metadata, tags, entity links, bounded title search, and ACL-filtered collections |
| `/api/v1/documents/{id}/*`, `/api/v1/downloads/{ticket}` | ACL-filtered reads, soft delete/restore/purge, one-use range-capable download tickets, render settings, and rendition tickets |
| `/api/v1/print-jobs/*` | ACL-checked in-memory PDF composition and job metadata; terminal outcomes are audited |
| `/api/v1/audit`, `/api/v1/audit/verify` | Auditor/admin index queries and a full file-chain walk that names the first bad `seq` |
| `/api/v1/vault/status` | Admin view of identity, size, blob/audit counts, `LATEST`, PostgreSQL version, and lock state; no key material |

PDFs are structurally inspected in the isolated worker in addition to the upload-time active-content
screen. Office archive validation rejects malformed packages and external relationships; actual
conversion requires a configured LibreOffice executable.

### 3.5 Checks

```bash
cd backend
../.venv/bin/pytest tests/unit -q
../.venv/bin/pytest tests/integration -q      # needs the 5433 cluster
../.venv/bin/pytest -q                        # everything
../.venv/bin/mypy app

cd ..
.venv/bin/ruff check backend
```

`mypy` must run from `backend/` so `pyproject.toml` supplies the strict configuration. The unit
tests use temporary directories only; no test touches a real vault. The integration tests create a
fresh database per test on the throwaway PostgreSQL 18 cluster, migrate it with Alembic, and drop
it afterwards. Set `DOCVAULT_TEST_PG_DSN` to use a different admin connection. Nothing is mocked
and SQLite is never used ([14 §8](14-development.md)).

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
| `app/vault/blobs.py` | [03 §5](03-vault-format.md) | **Partial** | DVC1 memory, declared-length, and incremental unknown-length writers; authenticated reader, header parsing, and padding. No `verify` or `salvage` command yet |
| `app/crypto/passphrase.py` | [05 §8](05-crypto.md) | **Done** | Minimum length, local common-phrase list, `zxcvbn` score ≥ 3 |

### 4.3 Vault

| Module | Design reference | State | Notes |
|---|---|---|---|
| `app/vault/layout.py` | [03 §2](03-vault-format.md), [03 §7](03-vault-format.md) | **Partial** | Layout, permissions, atomic writes, symlink/network/rename/fsync/casing probes. The Windows filesystem branch is code-reviewed, not executed |
| `app/vault/manifest.py` | [03 §3](03-vault-format.md) | **Partial** | Build, sign, verify, load, schema-version bump, unknown-field preservation. No operator-facing edit command |
| `app/vault/audit.py` | [03 §10](03-vault-format.md) | **Partial** | Monthly JSONL append and full-chain verification. No anchor file generation |
| `app/vault/lock.py` | [03 §11](03-vault-format.md) | **Done** | Exclusive create, 5-second heartbeat, 30-second staleness, audited forced takeover |
| `app/vault/init.py` | [09 §1](09-flows.md) | **Partial** | Vault identity and key wrapping only; TLS and database bootstrap are orchestrated by the CLI |
| `app/vault/dump.py` | [03 §9](03-vault-format.md) | **Partial** | DVD1 chunked authenticated encryption/decryption; integrated with backup operations |
| `app/vault/session.py` | [09 §1](09-flows.md), [05 §9](05-crypto.md) | **Partial** | Open, unlock, in-memory lock, close, status, unlock back-off. No automatic unlock, no idle lock, no live IPC |
| `app/vault/inspect.py` | [08 §1](08-ops.md) | **Done** | Read-only manifest, lock, blob, audit, dump-pointer, and TLS inspection |

### 4.4 API, CLI, and process

| Module | Design reference | State | Notes |
|---|---|---|---|
| `app/api/health.py` | [07 §1](07-api.md) | **Done** | `/healthz` and `/readyz` |
| `app/main.py` | [02 §8](02-architecture.md) | **Done for the implemented backend** | App factory mounts API routers, including audit/vault views, and recovers interrupted print jobs at startup |
| `app/cli.py` | [08 §1](08-ops.md) | **Partial** | `init`, `status`, `doctor`, live `unlock`/`lock`, `migrate`, `serve`, backup/restore/list, and `user create`; init rollback and the init→migrate→backup→list path are drilled. Verify, rotate, salvage, CLI restore in anger, and Windows IPC remain |
| `app/api/entities.py`, `app/services/entities.py` | [07 §4](07-api.md), [06](06-rbac-acl.md) | **Partial** | Encrypted entity/person/identifier CRUD, blind indexes, duplicate-identifier transaction locks, ETags, masked identifiers, and ACL-gated routes |
| `app/api/documents.py` | [07 §5](07-api.md) | **Partial** | Doc-type CRUD, tags/links/search, encrypted uploads/versions, purge, range downloads, and Office conversion; full route ACL matrix and real converter proof remain |
| `app/api/render.py`, `app/render/` | [11](11-frontend.md), [10 ADR-036/038](10-decisions.md) | **Partial** | Encrypted rendition cache, render settings, one-use tickets, isolated PDF/image rendering, and Office conversion; isolation is Linux-only |
| `app/api/printing.py`, `worker/printing.py` | [12](12-printing.md) | **Done** | In-memory composition, page ranges, authorization, job persistence/audit, saved recipes, startup recovery, and the documented paper/grid/margin/no-upscale contract |
| `app/api/operations.py` | [07 §6](07-api.md) | **Done** | Auditor/admin audit index and filters, chain verification, and admin vault status with no key material |
| `app/services/` | [06](06-rbac-acl.md) | **Partial** | Auth, account administration, transactional audit, ACL scope resolution, SQL-filtered lists, owner floor, and access logging; complete route-level ACL matrix remains |
| `worker/` | [02 §8](02-architecture.md) | **Partial** | Pipe worker for structural PDF inspection, rendering, Office conversion, and printing, with a hostile-input corpus; sandboxed with bubblewrap on Linux only |
| `frontend/` | [11](11-frontend.md) | **Not started** | Node and npm are absent on this development host |

### 4.5 Database

| Module | Design reference | State | Notes |
|---|---|---|---|
| `app/db/base.py` | [04 §1](04-data-model.md) | **Done** | Declarative base, naming convention, `citext`/enum helpers, shared regex constants |
| `app/db/enums.py` | [04 §3–7](04-data-model.md) | **Done** | Native PostgreSQL enums and the six capability bits (`print = 32`) |
| `app/db/models/` | [04](04-data-model.md) | **Done** | All 24 tables, constraints, partial indexes, deferred FK for `current_version_id` |
| `migrations/` | [04 §12](04-data-model.md), [14 §7](14-development.md) | **Done** | Alembic head `7e4c2b9a1f30`, render-ticket cache fields, triggers D-1–D-16, clean downgrade |
| `app/db/seed.py` | [13 §4](13-classification.md) | **Done** | 8 categories, 73 types, encrypted names, `side` hints, idempotent, refuses a reparented code with `SEED_CONFLICT` |
| `app/db/connect.py` | [08 §2.2](08-ops.md) | **Done** | App engine with the stored password injected at the process boundary, 5-second connect timeout, server-major check |
| `app/db/provision.py` | [08 §2.2](08-ops.md) | **Done** | Idempotent `docvault_app` role and database creation or adoption over the admin connection; validated identifiers |
| `app/db/credentials.py` | [08 §2.2](08-ops.md) | **Partial** | Machine-scope DPAPI on Windows (written, unexecuted); `0600` file beside the config on Linux; production refused on non-Windows. Keyring is not wired |
| `app/db/identity.py` | [05 §9](05-crypto.md), [08 §2.2](08-ops.md) | **Done** | Encrypted `vault_id` and `schema_version` rows, mismatch and newer-schema refusals |
| `app/db/migrate.py` | [14 §7](14-development.md) | **Done** | Alembic programmatic upgrade, revision probe, `DOCVAULT_MIGRATIONS` override, failures mapped to `MIGRATION_FAILED` |
| `app/db/bootstrap.py` | [09 §1](09-flows.md) | **Partial** | Migrate, seed, stamp, identity checks, first dump, and pre-migration dump hooks are wired; full CLI failure-injection remains |
| `app/db/backup.py` | [08 §3–4](08-ops.md) | **Partial** | Encrypted backup/restore, listing, `LATEST`, and retention have PostgreSQL integration coverage; CLI-level crash drills remain |
| `app/db/schema.py` | [04 §12](04-data-model.md) | **Done** | One source for the schema version and the initial revision |
| Repositories and query layer | [04](04-data-model.md) | **Partial** | API routers use SQLAlchemy queries directly; a separate repository layer and load testing are not implemented |
| `docvault migrate` wiring | [08 §2](08-ops.md) | **Done** | Applies revisions, seeds, stamps the identity, audits `database.migrate`, and supports `--force-lock` |

## 5. Test evidence

### 5.1 Unit suite — 204 passed

| File | What it proves |
|---|---|
| `test_crypto_keys.py` | Sub-key separation, a locked fingerprint vector, DVK1 round trip, wrong passphrase, tampered tag, absurd Argon2 cost, column AAD binding, blind-index normalisation, salt-scoped addresses |
| `test_blobs.py` | DVC1 header and padding, empty plaintext, tampering, wrong key, address mismatch, unknown flags and magic, declared/unknown-length streaming writers, size limits, short and long sources |
| `test_document_upload.py` | Multipart metadata ordering, magic-byte MIME checks, active-PDF keyword rejection, encrypted streaming (no plaintext `.part`), and oversized upload cleanup |
| `test_manifest.py` | Canonical JSON, signing, unknown-field preservation, tamper detection, fan-out rejection, wrong fingerprint, readable bytes round trip |
| `test_audit.py` | Zero hash, cross-month chaining, middle-entry tampering, the documented newest-line truncation limit, and refusal to append after a partial line |
| `test_lock.py` | Second writer refused, release, heartbeat record, stale detection, forced takeover, forced-takeover audit |
| `test_layout.py` | Layout creation, atomic write, private modes, symlink rejection, network filesystem rejection, relative root rejection, fan-out paths, idempotence |
| `test_config.py` | Development shape, unknown keys, remote DSN refusal, relative root refusal, missing file, comment-preserving root rewrite |
| `test_init.py` | Vault identity, second-init refusal, weak passphrase refusal, a write-failure rollback that leaves no half-initialised vault, unlock, wrong-passphrase audit, status without unlock, lock release |
| `test_credentials.py` | Credential path beside the config, `0600` round trip, missing and damaged files reported as `DB_CREDENTIAL_UNREADABLE`, production refused on non-Windows |
| `test_http.py` | `/healthz`, locked `/readyz`, ready `/readyz`, request-ID echo, problem documents, unknown route |
| `test_dump.py` | DVD1 header and chunk boundaries, authentication, tampering, truncation, wrong key, and no partial plaintext |
| `test_backup.py` | `LATEST` parsing, safe names, sortable timestamps, and dump retention |
| `test_acl.py` | Allow and deny closure for the six capability bits |
| `test_auth.py` | Username normalization, password rules, login throttle, and TOTP primitives |
| `test_control.py` | Private POSIX control socket, lock/unlock/status handling, and socket cleanup |
| `test_render_worker.py` | Isolated worker protocol, Office archive validation, PDF inspection, rendition rendering, and print layout composition |
| `test_render_hostile.py` | Empty, truncated, encrypted, active, embedded-file, oversized, and MIME-mismatched inputs are refused; transparency flattens to white; macro, zip-bomb, and incomplete Office archives are rejected |
| `test_print_contract.py` | A4/paper geometry, row-major grids, landscape, all paper/grid combinations, documented margin/gutter limits, duplex pairing, no upscaling in contain or fill, and fill cropping |

The unit suite is deliberately at the crypto and filesystem boundary. It proves the contracts
that are cheapest to get wrong, not that the product works end to end.

### 5.2 Integration suite — 97 passed

Every test creates a fresh database on the PostgreSQL 18.6 throwaway cluster, runs the Alembic
migration, and drops the database. The fixture skips, rather than falls back to SQLite, when the
cluster is absent.

| File | What it proves |
|---|---|
| `test_schema.py` | All 24 tables exist; downgrade empties the schema and upgrade restores it; native enums; capability masks (`print` requires `read`, mask ≤ 63); ACL trigger rejects deleted objects and unknown subjects; two-level `doc_types`; `version_count`; `current_version_id` ownership; version immutability; append-only audit (`UPDATE`/`DELETE`/`TRUNCATE`); legal-hold and delete-before-purge guards; deferred `self`-link rule; `updated_at` trigger; `settings` value/`value_enc` exclusivity; partial indexes |
| `test_seed.py` | 8 categories and 73 types; every type has a category; idempotent second run; renamed type survives; names are encrypted; front/back `side` hints; defaults match [13 §4](13-classification.md); a reparented code raises `SEED_CONFLICT` |
| `test_bootstrap.py` | Provisioning creates an unprivileged role that owns its database; a second run adopts the pair; the app role cannot `CREATE DATABASE` (SQLSTATE `42501`); migration is idempotent and reports the head; bootstrap seeds, stamps `vault_id` and `schema_version`, refuses a stranger's vault ID, and does not restamp on a second run; the server check accepts PostgreSQL 18 |
| `test_backup.py` | Encrypted `pg_dump`, restore into an empty database, dump TOC listing, vault-identity refusal, corruption/tampering detection, missing dumps, rotation, and `LATEST` durability on failure |
| `test_auth.py` | Login, session cookies, CSRF, password changes, lockout, and TOTP |
| `test_admin.py` | User/group lifecycle, ETags, last-admin protection, forced password change, and document-type CRUD/tree constraints |
| `test_acl.py` | Entity-scope union/deny behavior, filtered listing, owner floor, and durable denial audit |
| `test_entities.py` | Encrypted entity and identifier fields, identifier masking, duplicate-ID rejection, and the mandatory individual self-link |
| `test_documents.py` | Entity API ETags/masking, ACL-checked linked upload, encrypted blob persistence, idempotency replay, audited download, render cache, print jobs, and interrupted-job recovery |
| `test_acl_matrix.py` | Group allow/deny, immediate membership removal, upward/downward closure, multi-entity deny-wins, owner floor, restricted printing, admin exemption, break-glass, auditor read denial, soft-delete hiding, visible counts, entity ACL admin-only, self/privilege escalation, non-owner `manage_acl`, deny-admin-only, and before/after audit |
| `test_cli.py` | `init` writes the vault and its root, a second init and a weak/mismatched passphrase leave the vault untouched, `--reuse-vault` names the missing vault, and a real `init`→`migrate`→`backup`→`dump-list` run provisions, seeds, and dumps |
| `test_operations.py` | Admin/auditor audit listing and filters, reader denial, chain verification before and after tampering, CSRF on `POST /audit/verify`, and admin-only vault status with no key material |

The full suite, including auth, administration, ACL, entity, document upload/download, rendering,
print composition, audit/vault views, bootstrap, encrypted backup/restore, and CLI drills, passed:
**301 passed** against PostgreSQL 18.6 on 2026-10-29. Ruff lint/format and strict mypy checks also
pass.

### 5.3 S2a manually verified before the S2b worktree changes on 2026-10-28

A fresh development vault was created under `/tmp`, against the 5433 cluster, then inspected:

- `init` prompted for the admin password and passphrase, created the `docvault_app` role and
  `docvault` database, wrote `docvault-db.cred` with mode `0600`, created the layout, manifest,
  96-byte key file and audit entry, and rewrote `[vault].root` in the TOML file.
- It then applied revision `c02412ca4b8b` and seeded 8 categories and 73 types, reporting
  `schema 1 … 81 inserted` and auditing `database.migrate`.
- `status` reported the vault identity, `database: docvault (credential present)`, `lock: free`,
  `blob_count: 0`, `audit_entries: 3`, `last_dump: none`, and `audit_chain: ok`.
- `doctor` reported **PASS** for configuration, vault root, manifest, filesystem, key file, audit
  chain, PostgreSQL tools (18.6), credential, and server. TLS was **FAIL** because the run used
  `--no-tls`; the vault key check was **FAIL** because the shell had no terminal for the
  passphrase — the documented reason for that check.
- A second `migrate` was a no-op (`0 inserted`), and `init --reuse-vault` adopted the role and
  database, rewrote the credential, and left the manifest and key file untouched.
- The test database and role were dropped afterwards, so no throwaway identity is left in the
  cluster.

The schema was also checked by hand on `docvault_migrate` on port 5433: upgrade, downgrade to
base, and upgrade again; `alembic check` reports **No new upgrade operations detected**.

### 5.4 Not yet tested

| Gap | Consequence |
|---|---|
| Route-level ACL matrix across every entity/document/render/print endpoint | The resolver matrix in `06` §10 is covered; each route's wiring is tested only on its principal path |
| CLI `restore`, `user create`, and Windows `init` | `init`→`migrate`→`backup`→`dump-list` and init rollback are exercised; restore is covered at the function level, and the Windows DPAPI path is unexecuted |
| Windows filesystem, path handling, and lock/unlock IPC | The production target is unexercised; local control IPC is POSIX Unix-socket only |
| DPAPI credential sealing | The ctypes call is written and reviewed, never executed; the Linux file path is what the tests cover |
| `serve` against a mismatched database | The identity check is exercised through `doctor` and the integration tests, not by starting the HTTPS listener |
| Concurrent processes and heartbeat failure | Stale-lock takeover is tested by writing a file, not by killing a live writer |
| Large streamed uploads and disk-full behaviour | Streaming is tested with small payloads and an enforced size cap, not a 100 MB document or disk-full fault |
| Rendition cleanup failures and orphaned ciphertext after filesystem errors | Database/cache behavior and ordinary eviction are tested; disk-full and unlink fault injection remain |
| Global metadata search and mutable settings | `docs/07` §6 names `GET /search` and `GET`/`PUT /settings`; the contracts do not define a response shape or an allow-list, so neither route is built |
| Operational `verify`, `rotate-passphrase`, `rotate-vmk`, and `salvage` commands | `status` and `doctor` cover read-only inspection; the mutating operator commands in `docs/08` §5 are not implemented |
| Crash injection during blob write or dump | `init` rollback is fault-injected; blob and dump writes are covered by tamper/truncation tests, not by an injected filesystem failure |
| TLS handshake with a real client | Certificates are generated and fingerprinted, not used by a browser |
| Query behaviour under load | Functional database paths are covered; there are no volume or performance tests |
| Frontend | No code; excluded from the backend completion scope |

## 6. Deviations and open gaps

Each item names what the design expects, what the code does, and how it closes. Temporary gaps are
allowed only while this table says so; a gap without a slice is a defect.

| ID | Design expects | Current build | Resolution |
|---|---|---|---|
| IMP-01 | `docvault init` provisions the role, database, schema, seed catalogue, and first dump ([08 §2](08-ops.md), [09 §1](09-flows.md)) | A CLI drill now provisions/adopts a real pair, seeds, writes the first dump, and exercises rollback, refusal, and passphrase failures | **Closed (2026-10-29, Linux); Windows bootstrap is IMP-13** |
| IMP-02 | A running service can be unlocked and locked through IPC ([08 §7](08-ops.md)) | Live local control uses a private POSIX Unix socket, revokes sessions on lock, and drops in-memory keys | **Done on Linux; Windows named-pipe equivalent deferred to S8** |
| IMP-03 | Automatic unlock uses DPAPI/keyring when opted in ([15 §6.3](15-production-setup.md)) | Automatic vault-key unlock is not implemented; `serve` requires interactive unlock | **Deferred to S8** |
| IMP-04 | Schema, Alembic migrations, seeded document types, constraints, triggers, and indexes ([04](04-data-model.md)) | All 24 tables and the seed catalogue exist at head `7e4c2b9a1f30`; downgrade and upgrade tests pass | **Closed (S1)** |
| IMP-05 | Encrypted `DVD1` dumps, `LATEST`, backup, restore, and pre-migration dumps ([03 §9](03-vault-format.md), [08 §3–4](08-ops.md)) | Format, commands, hooks, PostgreSQL backup/restore, and CLI backup/list drills pass; CLI `restore` remains function-level only | **Implemented; CLI restore drill open** |
| IMP-06 | Database credential stored in DPAPI or the OS keyring, never in TOML ([02 §6.3](02-architecture.md)) | Linux development uses a `0600` credential file; DPAPI is written but unexecuted and keyring is not wired | **Deferred to S8 production proof** |
| IMP-07 | `doctor` checks the live database and its version ([08 §1](08-ops.md)) | Credential, server major, identity, and schema checks are covered | **Closed (S2a)** |
| IMP-08 | Auth, sessions, CSRF, lockout, roles, and the single ACL gate ([06](06-rbac-acl.md), [07 §2](07-api.md)) | Routes use ACL gates and durable access audits; the documented resolver matrix is covered, but each route is not yet exercised under every scope | **Partial; remaining route-level matrix** |
| IMP-09 | Entities, persons, identifiers, documents, versions, uploads, downloads, and audit writes ([07 §4–5](07-api.md)) | CRUD, doc types, tags/links/search, encrypted uploads/versions, purge, range downloads, structural PDF inspection, and the hostile-input corpus are implemented | **Implemented; route-level ACL matrix remains** |
| IMP-10 | Office intake converts once at ingest; previews are encrypted renditions ([10 ADR-038](10-decisions.md), [11](11-frontend.md)) | Linux-isolated worker, encrypted previews/cache, and converter wiring are implemented; actual LibreOffice execution and non-Linux sandbox remain unverified | **Partial; platform/converter validation** |
| IMP-11 | Print composition produces one PDF in memory, with no stored artifact ([12](12-printing.md)) | Composition, job records, terminal audit, crash recovery, print authorization, and the documented paper/grid/margin/no-upscale contract are covered; presets are built-in values and `07` defines no preset route | **Closed (2026-10-29)** |
| IMP-12 | React frontend served from the same origin ([11](11-frontend.md)) | No frontend | **Deferred; outside backend scope** |
| IMP-13 | Windows production installation, service, MSI, and filesystem behaviour ([15](15-production-setup.md)) | Only Linux development paths have been executed | **Deferred; outside backend scope** |
| IMP-14 | Python `3.14.10` ([02 §6.1](02-architecture.md)) | Local interpreter is `3.14.4`; no feature depends on the patch level | **Deferred to release build** |
| IMP-15 | `doctor` is a read-only inspection | Its filesystem probe writes short-lived probe files under `tmp/`. It never creates missing vault folders or modifies content, but the filesystem must be writable | Documented behaviour; no action unless a read-only doctor is required |
| IMP-16 | The design is the base for code | `backend/app/crypto/blobs.py` was moved to `backend/app/vault/blobs.py` to match the layout in [02 §8](02-architecture.md) | Closed 2026-10-28 |
| IMP-17 | `GET /audit`, `POST /audit/verify`, and `GET /vault/status` ([07 §6](07-api.md)) | Implemented with role checks, CSRF on the POST, file-chain verification, and no key material in the vault response | **Closed (2026-10-29)** |
| IMP-18 | `GET /search` and `GET`/`PUT /settings` ([07 §6](07-api.md)) | Not built: `07` defines neither the combined result shape nor the settings allow-list | **Deferred until the contract names both** |
| IMP-19 | `docvault verify`, `rotate-passphrase`, `rotate-vmk`, and `salvage` ([08 §5–6](08-ops.md)) | `status`/`doctor` cover read-only inspection; the mutating commands are not implemented | **Deferred to the operational slice** |

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

### S1 — Database foundation — **done 2026-10-28**

**Build:** SQLAlchemy 2.0 models for every table in [04](04-data-model.md), Alembic configuration
and the first migration, documented enums and constraints, partial indexes, updated-at and
immutability triggers, and the seeded two-level `doc_types` catalogue (eight categories and the
types listed in [13 §4](13-classification.md)). Add a PostgreSQL 18 fixture that creates a
temporary database on the throwaway cluster.

**Exit criteria:** migration upgrades an empty database and downgrades cleanly; constraints reject
bad rows; the seed is idempotent; integration tests run against real PostgreSQL, never SQLite.

**Delivered:** 24 models under `app/db/models/`; initial revision `c02412ca4b8b` with triggers
D-1–D-16 and an explicit enum teardown on downgrade; `app/db/seed.py` with 8 categories and 73
types; follow-up revision `7e4c2b9a1f30` adds render-ticket cache fields. Contract documents
updated for `print = 32`, `gender` values, `settings.value`, `row_version`, D-4/D-6/D-10, and the
version immutability list.

### S2 — Provisioning, credentials, and dumps

Split in two so the database path could be tested before the dump format existed.

#### S2a — Provisioning, credentials, and `migrate` — **done 2026-10-28**

**Build:** `init` creates the `docvault_app` role and `docvault` database from an admin
connection, stores the credential outside the vault, applies the migrations, seeds the catalogue,
and stamps the vault identity. Wire the real database checks into `doctor` and `serve`.

**Exit criteria:** a fresh `init` produces a database the app can open; `doctor` passes on a
correct host; a wrong vault ID refuses.

**Delivered:** `app/db/` gained `connect`, `provision`, `credentials`, `migrate`, `identity`,
`schema`, and `bootstrap`; `init` grew `--admin-dsn`, `--no-database`, and `--reuse-vault`;
`docvault migrate [--force-lock]` applies revisions, seeds, stamps, and audits; `doctor` checks the
credential, live server, identity, and schema; `serve` refuses a mismatched database;
`MIGRATION_FAILED` was added to the error catalog. 6 integration tests and 8 credential unit
tests; the suite is 75 unit + 39 integration. Verified end to end against the 5433 cluster.

#### S2b — Encrypted dumps — **implemented; CLI fault validation remains**

**Build:** the `DVD1` chunked container and its `LATEST` pointer ([03 §9](03-vault-format.md)),
`docvault backup`, `docvault restore`, and `docvault dump-list` ([08 §3–4](08-ops.md)), the first
dump at the end of `init`, the pre-migration dump at the start of `migrate`, and the real
last-dump line in `status`.

**Exit criteria:** a dump restores into an empty cluster; a truncated dump fails its tag check and
is refused; a wrong passphrase or wrong vault ID refuses; `LATEST` only moves after the dump is
durable.

**Present in the current worktree:** the DVD1 format, `LATEST` pointer, `backup`,
`restore`, and `dump-list`; initial and pre-migration dump hooks; latest-dump reporting in `status`;
unit and PostgreSQL integration tests. The full suite passes 226 tests, with Ruff and mypy clean.
Full CLI crash/failure injection remains before S2b can be marked done.

### S3 — Authentication, sessions, and the permission gate — **in progress**

**Build:** login, logout, session cookie, CSRF, lockout, password change, user administration, and
one ACL resolver implementing [06 §5](06-rbac-acl.md). Add audit database writes in the same
transaction as the change. Add live unlock/lock IPC or a documented single-process replacement.

**Exit criteria:** the [06 §10](06-rbac-acl.md) matrix passes; unauthorised requests return `404`
rather than `403` where the design requires it; every allow and deny is audited.

**Present in the current worktree:** login/logout, session and CSRF validation, temporary-password
enforcement, password changes, TOTP enrollment/verification/disable, process-local login throttling,
admin user/group routes, database audit writes, capability closure, document/entity ACL replacement,
document owner floor, restricted-print checks, and SQL-filtered document visibility. Access denials
are committed independently so a rejected request cannot roll back its audit record. PostgreSQL
integration tests cover the principal resolver, owner-floor, and audit cases. Entity and document
resource routes use the gate, and private POSIX IPC provides live lock/unlock with session revocation.
The complete route-level ACL matrix and Windows named-pipe equivalent remain open.

### S4 — Entities, documents, and versions — **in progress**

**Build:** entity and person CRUD, identifier blind indexes, document create/update/soft-delete,
version upload and download, blob write and read through `vault/blobs.py`, MIME sniffing, format
rejection (including TIFF), size limits, and idempotent retries.

**Exit criteria:** [09 §3–5](09-flows.md) and [09 §9–10](09-flows.md) work end to end; a document
is unreadable on disk; an unauthorised download fails without leaking existence.

**Present in the current worktree:** encrypted entity/person/identifier operations, audited
identifier reveal, version-1 and appended encrypted uploads, doc-type CRUD, tags/links, bounded
encrypted-title substring search, soft-delete/restore/purge, one-use user/IP-bound range downloads,
and Office upload conversion to encrypted derived PDFs. Entity and category/date filters,
metadata-plus-content idempotency, and structural PDF inspection in the worker are covered.
Downloads authenticate the complete encrypted blob before selecting a range. Full ACL-matrix and
hostile-input corpus coverage remain open.

### S5 — Previews and Office intake — **implemented with platform/converter validation gaps**

**Build:** the separate render worker with no vault key and no network, encrypted rendition cache,
JPEG/PNG/PDF previews, one-time Office-to-PDF conversion at ingest, and cache eviction.

**Delivered:** a pipe-based Linux bubblewrap worker with no vault mount/key or network, PDF/image
rendering and inspection, encrypted rendition cache with eviction, render settings and one-use
tickets, Office archive checks, and one-time conversion when a converter is configured. Without a
converter Office uploads fail with `415`.

**Remaining:** execute real LibreOffice conversion and the full hostile-input corpus; implement and
test a supported non-Linux sandbox before production deployment.

### S6 — Print composition — **implemented with preset/layout coverage gaps**

**Build:** the layout maths and composer from [12](12-printing.md), page ranges, grid cells, duplex,
presets, one audit event per job, and no stored print artifact.

**Delivered:** grid composition, page ranges, duplex settings, saved render recipes, per-document
print authorization, job/item persistence, one terminal audit event, in-memory PDF response,
metadata routes, and startup recovery of interrupted jobs.

**Remaining:** preset management and exhaustive golden-page comparisons for all grids/paper sizes.
Restricted-print authorization and page/sheet counts have focused integration coverage.

### S7 — Frontend — **deferred; outside backend scope**

**Build:** the screens in [11](11-frontend.md) on React 19, TypeScript, Vite, and TanStack Query,
served by FastAPI from the same origin. Implement the viewer, print queue, and accessible table
patterns before polish.

**Exit criteria:** the [07 §10](07-api.md) contract tests exist; keyboard-only filing and printing
work; no key material reaches the browser.

### S8 — Packaging and production proof — **deferred**

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
| 2026-10-28 | S1: database foundation. 24 models, Alembic revision `c02412ca4b8b`, triggers D-1–D-16, seed catalogue (8 categories, 73 types), 33 integration tests; 100 tests total. `04` synced for `print = 32`, `gender`, `settings.value`, `row_version`, D-4/D-6/D-10/D-16, and version immutability. `08` no longer claims the seed is a migration. `14` records the integration command and `DOCVAULT_TEST_PG_DSN`. |
| 2026-10-28 | S2b work-in-progress status: encrypted dumps and backup/restore wiring are present. The complete backend suite passes (125 unit, 59 integration); CLI `init`/`migrate` dump orchestration remains unverified. |
| 2026-10-29 | Earlier S3/S4 checkpoint: entity and document routes were ACL-gated; version appends, request-bound idempotency, single byte-range downloads, category/date filters, and admin purge with legal-hold/retention guards were implemented. Remaining gaps at that checkpoint are closed or updated in the later entry below. |
| 2026-10-29 | Backend completion pass: added doc-type CRUD and ETag/tree guards, live POSIX lock/unlock IPC, isolated rendering/Office intake, print composition and interrupted-job recovery. Full suite: 226 tests; Ruff and mypy pass. Windows IPC/sandboxing, custom print presets, exhaustive ACL/golden-layout tests, and CLI failure drills remain explicitly open. |
| 2026-10-29 | Backend gap closure: print layout limits and no-upscale composition, a hostile-input worker corpus, the `06` §10 ACL resolver matrix, CLI init/migrate/backup/list drills with rollback, and audit/vault-status routes. Re-saving a delegate's unchanged ACL no longer trips escalation checks. Full suite: 301 tests; Ruff and mypy pass. `/search`, `/settings`, and the mutating operator commands are recorded as contract-deferred in IMP-18/19. |
