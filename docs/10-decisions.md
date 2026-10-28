# 10 — Decision Log

> **In plain words:** Every important choice is written down here, along with what we rejected
> and what it would cost to change our mind. If you wonder "why is it like this?", the answer is
> on this page.
>
> **Read this if:** you are about to change a design decision, or you need to know whether a
> choice is easy or expensive to revisit.

How to read the reversal cost:

| Cost | Meaning |
|---|---|
| **Cheap** | About a day of work |
| **Moderate** | About a week |
| **Expensive** | Weeks of work, or a format migration |

---

## 1. Index

| ID | Decision | What it means in practice | Status | Reversal |
|---|---|---|---|---|
| 001 | FastAPI + PostgreSQL, single backend worker | One process serves the app and talks to the database | Accepted | cheap |
| 002 | The vault folder is the backup; the dump lives inside it | Everything is in one folder, including the database dump | Accepted | moderate |
| 003 | Relative paths everywhere; one re-pointable absolute root | The database stores no absolute paths except one | Accepted | expensive |
| 004 | Logical dumps only; the PostgreSQL data folder never goes in the vault | Backups are SQL dumps, not raw database files | Accepted | expensive |
| 005 | HMAC content-addressed blob filenames, 2+2 folder fan-out | File names on disk come from content, not from users | Accepted | expensive |
| 006 | Envelope encryption; the passphrase-wrapped vault key lives in the vault | One passphrase unlocks one master key, stored wrapped | Accepted | expensive |
| 007 | Separate HKDF sub-keys for separate jobs | Each job gets its own key derived from the master | Accepted | expensive |
| 008 | AAD binds each encrypted column to its table and column | An encrypted value is tied to the column it belongs in | Accepted | moderate |
| 009 | Blind indexes instead of searchable encryption | Exact lookup uses keyed fingerprints, not plaintext | Accepted | moderate |
| 010 | A file key per version, wrapped inside the blob | Each version carries its own key inside the file | Accepted | expensive |
| 011 | No crypto-shredding; best-effort overwrite on purge | Purging overwrites bytes; it cannot destroy old backups | Accepted | moderate |
| 012 | No de-duplication; a random salt per version | Identical files are stored separately, on purpose | Accepted | moderate |
| 013 | Identifier uniqueness is advisory, not a database constraint | Duplicate IDs are flagged, not blocked by the database | Accepted | cheap |
| 014 | Identifiers are rows, not columns | New ID types need no schema migration | Accepted | moderate |
| 015 | Entity and Person are separate tables | People and organisations are modelled separately | Accepted | moderate |
| 016 | Per-document permissions, inheriting by default, with groups and no folders | A document inherits permissions unless set explicitly | Accepted | moderate |
| 017 | Permissions are application-level, not a cryptographic boundary | Permissions stop colleagues, not someone with the passphrase | Accepted | expensive |
| 018 | Deny wins; union across linked entities; 404 rather than 403 | A deny beats an allow; hidden documents look missing | Accepted | moderate |
| 019 | Six capabilities, with `view`, `read`, and `print` separate | Seeing, reading, and printing are separate rights | Accepted | moderate |
| 020 | Metadata-only search; no extraction or OCR | Search covers metadata only, never document text | **Superseded by 033** for previews; the search half stands | moderate |
| 021 | Native backend; PostgreSQL installed and managed by the operator; network filesystems refused | Install natively; never put the vault on a network share | Accepted | expensive |
| 022 | The web app is served from the same origin as the API; no CORS | The web app and API share one origin, so no CORS setup | Accepted | cheap |
| 023 | Admin-created accounts, Argon2id, optional TOTP | Admins create accounts; the second factor is optional | Accepted | cheap |
| 024 | Audit as hash-chained JSONL plus a queryable database index | Audit is append-only files plus a query table | Accepted | moderate |
| 025 | UUIDv7 identifiers | IDs are time-sortable and safe to create before insert | Accepted | moderate |
| 026 | Editors soft-delete; admins purge; legal hold blocks purge | Delete is reversible; purge is admin-only | Accepted | cheap |
| 027 | Store expiry dates; defer reminders | Expiry dates are stored; reminders are not built | Accepted | cheap |
| 028 | Require `If-Match` on every mutation | Every change must name the version it started from | Accepted | cheap |
| 029 | TLS private authority lives outside the vault | Certificates live outside the vault | Accepted | cheap |
| 030 | Pin "latest stable minus one" and re-check quarterly | Pin mature versions and review them every quarter | Accepted | cheap |
| 031 | PostgreSQL is operator-managed; the app is a client only | The database server is a prerequisite, not something we ship | Accepted | moderate |
| 032 | Database dumps are encrypted in the vault | The dump is a ciphertext container, not a readable backup file | Accepted | moderate |
| 033 | Previews and renditions are allowed; renditions are encrypted, content-addressed, and evictable | You can see a document on screen, and the rendered copy on disk is still ciphertext | Accepted | expensive |
| 034 | `print` is a capability of its own | The office can grant viewing without granting copies | Accepted | moderate |
| 035 | Printing is client-side; the server builds a PDF and stores nothing | The user prints at their desk; the app never touches a spooler | Accepted | moderate |
| 036 | Edits are a render recipe, not a version | Brightness and crop change the picture, not the record | Accepted | moderate |
| 037 | Front and back are separate documents; `side` is a hint only | No pairing rules, no validation, no guessing | Accepted | cheap |
| 038 | Office files are intake-only and converted once to PDF | DOC, DOCX, and ODT are accepted, printable, and never edited in place | Accepted | expensive |
| 039 | The render worker is a separate process with no key material | The largest attack surface cannot reach the vault key | Accepted | moderate |
| 040 | Categories are a two-level `doc_types` tree, not folders | Every document has one type, and every type belongs to one category | Accepted | cheap |
| 041 | Sensitivity changes policy, never storage | There is no unencrypted tier, at any level | Accepted | expensive |
| 042 | TIFF is not an accepted format | PDF already covers multi-page and bilevel scans | Accepted | cheap |
| 043 | Development runs the same PostgreSQL major and code paths as production | No SQLite or mocked database; a throwaway cluster, but the real schema | Accepted | cheap |

---

## 2. The decisions

### ADR-001 — FastAPI + PostgreSQL, one worker
**Decision.** Python 3.14, FastAPI, PostgreSQL 18, and uvicorn with a single worker.
**Rejected.** Multiple workers, because the decrypted vault key would be copied into each one
and the vault lock would multiply. SQLite, because Postgres was requested and `jsonb`, partial
indexes, and concurrency are useful. asyncpg, because psycopg3 fits the SQLAlchemy stack better.
**Consequence.** One process caps throughput, but that cap is far above what a 20-person office
needs. Heavy crypto work runs in a thread pool. Exact pins are in `02-architecture.md` §6.1 and
governed by ADR-030.

### ADR-002 — The vault folder is the backup
**Decision.** The encrypted database dump, blobs, audit files, and wrapped key all live under one
root. Moving to new hardware means copy the folder and restore the dump.
**Rejected.** Keeping the database and content in separate backup streams, because that is two
things to keep in sync and people get it wrong. Rebuilding from the journal alone, because event
sourcing is overkill for a records tool.
**Consequence.** The dump becomes essential, and its schedule defines how much data can be lost.
The journal is a safety net, never a requirement. The dump is itself encrypted (ADR-032), so the
"one folder" promise does not weaken the "nothing readable on disk" promise. The one thing the
folder cannot carry is the database server, which is now an operator prerequisite (ADR-031).

### ADR-003 — Relative paths only
**Decision.** Blob references are relative to the vault. Exactly one absolute setting exists,
`settings.vault_root`, and it is re-pointed on restore.
**Rejected.** Symlinks or absolute paths in rows, which break on every move. A path-rewriting
migration after restore, which is error-prone and unnecessary if the path was never stored.
**Consequence.** Restore must check that `vault_id` matches before rewriting the root. Otherwise
the wrong folder silently starts taking writes.

### ADR-004 — Logical dumps only
**Decision.** Use `pg_dump --format=custom` and restore with `pg_restore`.
**Rejected.** Physical base backups, which are tied to a version and an OS. Putting the
PostgreSQL data folder inside the vault, which brings absolute paths, `postmaster.pid`,
permission problems, and cross-version fragility.
**Consequence.** Restores are slower, but portable, and the dump can be inspected.

### ADR-005 — HMAC content addressing
**Decision.** Store blobs at `blobs/<aabb>/<64-hex>.blob`, where the address is an HMAC over the
salted plaintext.
**Rejected.** Original filenames on disk, which bring Unicode, case, path-traversal, reserved-name,
and information-leak problems. Random UUID names, which give no integrity check and make orphans
unidentifiable. Raw SHA-256, which lets anyone with folder access confirm that a known file is
present.
**Consequence.** Verification is a decrypt-and-recompute pass, and a corrupt file is detectable
without the database.

### ADR-006 — The passphrase-wrapped vault key lives in the vault
**Decision.** The vault key is wrapped by an Argon2id-derived key and stored at
`keys/kek.wrapped`.
**Rejected.** An OS keyring only, which needs manual key provisioning after a move and breaks the
primary requirement. No encryption, which fails the stolen-disk threat. A key file elsewhere on
the host, which has the same problem.
**Consequence.** A stolen vault is protected by the passphrase alone. That is the single most
important operational fact in the system (`01` R-8).

### ADR-007 — Separate sub-keys
**Decision.** Derive `file`, `meta`, `bidx`, `addr`, `manifest`, and `fp` keys from the vault key.
**Rejected.** One key for everything, which gives no domain separation: a leak in one use weakens
all of them.
**Consequence.** Changing the passphrase re-wraps 32 bytes. Nothing is re-encrypted.

### ADR-008 — AAD-bound column encryption
**Decision.** Set `AAD = "<table>.<column>"` on every encrypted value.
**Rejected.** No AAD, which makes ciphertexts interchangeable between columns.
**Consequence.** Renaming a column needs a data migration. That is acceptable and rare.

### ADR-009 — Blind indexes
**Decision.** Use `HMAC(bidx_key, type|normalised)` for exact lookup of identifiers, names, and
tags.
**Rejected.** Deterministic encryption, which has the same weakness with more complexity.
Searchable-encryption schemes, which are immature, slow, and hard to audit. Plaintext indexes,
which fail the requirement.
**Consequence.** Equality only. No prefix or fuzzy search on encrypted fields. Frequency is
leaked, which is acceptable for typed identifiers.

### ADR-010 — The file key lives inside the blob
**Decision.** Each blob carries its own file key, wrapped under `file_kek`.
**Rejected.** Keys only in the database, where a lost or stale dump makes content unrecoverable.
A separate keyring file, which is one more thing to keep in sync and has the same
self-containment problem.
**Consequence.** Blobs can be decrypted with the passphrase alone, which enables `salvage`. It
also makes crypto-shredding impossible (ADR-011).

### ADR-011 — No crypto-shredding (this replaced the original plan)
**Status.** Revised during design review.
**Decision.** Purge overwrites the blob with random bytes, fsyncs, and unlinks it. No key is
destroyed, because the key is inside the blob.
**Rejected.** Document-level keys in the database, destroyed on purge. That was the original idea
and it would have delivered real crypto-shredding. We rejected it because it makes content
unrecoverable when the database and all its dumps are lost, which contradicts the "folder is the
backup" promise in ADR-002 and ADR-010.
**Consequence.** Deleted content may survive in backups taken before deletion. The only real
control is backup retention. **This is the one decision a product owner may reasonably reverse.**
If you do, say so explicitly: it changes the schema (a `document_keys` table) and the restore
rules.

### ADR-012 — No de-duplication
**Decision.** A random 16-byte salt per version goes into the address calculation, so identical
files produce different blobs.
**Rejected.** De-duplication, which saves space but leaks equality between entities and couples
the lifetimes of unrelated documents.
**Consequence.** Storage grows linearly with versions. For a records office that is the right
trade. Revisit only if storage becomes a real constraint.

### ADR-013 — Identifier uniqueness is advisory
**Decision.** A non-unique index on `(id_type, value_blind)`. The API returns `409` with the
conflicting entity, and an operator may record `duplicate_ack_of`.
**Rejected.** A hard unique constraint, where one typo or one legacy record blocks all work.
Silent duplicates, which defeat the purpose.
**Consequence.** Duplicates are possible but never invisible. Every acknowledgement is audited.

### ADR-014 — Identifiers are rows
**Decision.** Use `identifiers(id_type, value_enc, value_blind, ...)`.
**Rejected.** A column per type (`pan_number`, `gstin`, ...), which needs a migration for every
new identifier and duplicates the encryption logic.
**Consequence.** Easy to extend. Queries join instead of reading a column.

### ADR-015 — Entity and Person are separate
**Decision.** `entities` holds legal subjects, `persons` holds natural persons, and
`entity_person` holds roles such as `self`, `director`, `signatory`, and `guarantor`.
**Rejected.** One table with a nullable type flag, where directors become pseudo-entities.
Person-only, which cannot model companies.
**Consequence.** An individual is an entity linked to itself in the `self` role, enforced by a
constraint.

### ADR-016 — Per-document permissions with inheritance
**Decision.** Document permissions are explicit, but by default they inherit from linked
entities, which in turn default to the vault role. No folder tree.
**Rejected.** Pure per-document permissions, where every new document needs hand-maintained
grants and access rots. Global roles only, which the requirement rules out.
**Consequence.** Two modes to explain, not three. The interface must make "inherit versus
explicit" obvious, and the "who can see this" panel becomes mandatory.

### ADR-017 — Permissions are not a crypto boundary
**Decision.** Document the limitation rather than engineer around it.
**Rejected.** Per-user key wrapping in v1, because key escrow and recovery costs dwarf the
benefit at this scale.
**Consequence.** The passphrase is the perimeter. A future per-user wrapping path is described in
`05` §12 and adds to the blob format rather than replacing it.

### ADR-018 — Deny wins; 404 over 403
**Decision.** Take the union of allows, subtract any deny, and return `404` for documents the
user cannot see.
**Rejected.** Most-specific-wins, where a document-level allow silently overrides an entity deny.
`403` for invisible documents, which confirms that they exist.
**Consequence.** To grant one document despite an entity deny, the deny itself must be removed.
That is intentional, and the interface must explain it.

### ADR-019 — `view`, `read`, and `print` are separate
**Decision.** `view` means metadata; `read` means content; `print` means "may produce copies
through the app". `read` implies `view`; `print` implies `read`; denies close downward.
**Rejected.** A single `read`, which either gives auditors content or takes away their ability to
see that a document exists. Also rejected: making print free with read, which is how the office
ends up unable to say "you may look, but not copy".
**Consequence.** One extra bit, a clearer auditor role, and one correction to the resolution
algorithm: implies must be expanded on both the allow and the deny mask before subtraction
(`06` §5). `print` is a policy control, not a boundary; R-11 says so.

### ADR-020 — Metadata-only search
**Decision.** No text extraction, OCR, or full-text search. No thumbnails either — **this half is
superseded by ADR-033**, because the product needs a viewer.
**Rejected.** Extracted text in Postgres, which is a plaintext copy of every document and
undermines the encryption. On-demand extraction at query time, which has unpredictable latency.
**Consequence.** Users cannot search inside documents. Name search is exact blind-index lookup
plus a bounded in-memory prefix scan (`07` §4). Previews and thumbnails now exist, but no
extracted text does. That distinction is the one that matters: a rendered page is a picture, not
an index.

### ADR-021 — Native backend, no network filesystems
**Decision.** Install the app natively per OS, and refuse to open a vault on SMB, NFS, FUSE, or a
container bind mount. PostgreSQL is installed separately by the operator (ADR-031).
**Rejected.** Docker Compose, which looks attractive until Windows and macOS bind mounts break
`fsync` and atomic rename. A Linux-only first release, which contradicts the stated requirement.
**Consequence.** Two installers (Windows for production, Linux for development) and a two-platform
test matrix. macOS is out of scope for v1: the vault format is OS-neutral, but an untested
platform is not a supported platform.

### ADR-022 — Same-origin web app
**Decision.** FastAPI serves the built frontend. No CORS.
**Rejected.** A separate origin or port, which adds cookies, CORS, and CSRF complexity for no
benefit.
**Consequence.** The frontend deploys with the backend. Development uses a proxy so the origins
still match.

### ADR-023 — Admin-created accounts, optional TOTP
**Decision.** No self-registration. Argon2id passwords. TOTP optional per user and enforceable
later.
**Rejected.** Mandatory TOTP, which is a support burden in a small office. Password-only forever,
because account takeover remains a threat even though the passphrase protects data at rest.
**Consequence.** Creating an account is a manual admin step, and onboarding is documented.

### ADR-024 — Audit as JSONL plus a database index
**Decision.** Authoritative append-only JSONL in the vault, hash-chained, plus a database table
for queries.
**Rejected.** Database-only audit, which a DBA or a bug can rewrite. File-only audit, which
cannot be queried.
**Consequence.** Two places to keep consistent. The database row is written in the same
transaction, and the file append happens right after commit. Known gap: the newest entries can be
truncated (R-6).

### ADR-025 — UUIDv7
**Decision.** Application-generated UUIDv7 primary keys.
**Rejected.** Serial integers, which leak volume and complicate merges. UUIDv4, which has poor
index locality at millions of rows.
**Consequence.** IDs are sortable and safe to generate before insert, which simplifies the upload
transaction.

### ADR-026 — Soft delete, admin purge, legal hold
**Decision.** Editors soft-delete and restore. Only admins purge, and only after a soft delete.
Legal hold blocks purge.
**Rejected.** Hard delete for editors, where one misclick destroys a record. No purge at all,
which makes retention obligations impossible.
**Consequence.** Purge is rare, deliberate, reasoned, and audited (`09` §12).

### ADR-027 — Store expiry, defer reminders
**Decision.** `documents.expiry_date` and `doc_types.retention_months` exist in v1. No alerts.
**Rejected.** Deferring the columns too, which only means a migration later for no saving.
**Consequence.** "Expiring soon" is a query, not a job. Reminders are a later feature.

### ADR-028 — `If-Match` is mandatory on mutations
**Decision.** Return `428` when it is absent and `409` when it does not match.
**Rejected.** Last-write-wins, which silently loses metadata. Optional preconditions, which
nobody uses.
**Consequence.** The interface must carry ETags and handle conflicts gracefully. Worth it.

### ADR-029 — TLS material outside the vault
**Decision.** The certificate authority and server key live in the OS config folder.
**Rejected.** Putting them inside the vault, which puts a private key in every backup copy and
lets a restored vault reuse a possibly leaked certificate.
**Consequence.** A restored vault gets a new certificate, and clients re-import the CA once.

### ADR-030 — Pin "latest stable minus one" and re-check quarterly
**Decision.** Every dependency is pinned to an exact version in a lockfile, and the pins are
recorded with their release dates in `02-architecture.md` §6.1. The default target is the newest
**stable, mature** release, which is not always the highest number.

| Component | Pinned | Newer exists | Why not the newer one |
|---|---|---|---|
| Python | 3.14.10 | 3.15.2 | 3.15 is 19 days old. Packaging tools and prebuilt libraries lag a new minor, and the 3.15 macOS builds default to free-threading, which complicates packaging. |
| PostgreSQL | 18.6 | 19 RC1 | 19 has not reached general availability. A production database does not run on a release candidate. |
| TypeScript | 7.0.2 | 7.1 beta | Beta releases are not shipped. |
| Vite | 8.3.5 | 6.4.5 | 6.4.x is the *maintenance* line, not the current line. A higher number is not always newer. |
| Node.js | 24.22.1 LTS | 26.12.1 | 26 reaches LTS on 2026-10-28. Build tooling is adopted one LTS cycle behind on purpose. |

Everything else is at the latest stable patch as of 2026-10-28.

**Rejected.** Tracking `@latest` or floating ranges at build time, which gives unreproducible
builds and is the easiest supply-chain attack. Freezing for a year, which accumulates security
debt — especially in the crypto and database layers. Pinning the absolute latest of everything
regardless of ecosystem readiness, which breaks the installer on the two operating systems that
are hardest to test.

**Consequence.** Upgrades are deliberate events, never background surprises. Security patches go
in within 7 days. Minors go in quarterly, after the permission, crypto, and vault round-trip tests
pass on both supported operating systems. Database majors go through a dump and restore drill. The
version table is re-checked quarterly, and a stale table is a documentation bug.

### ADR-031 — PostgreSQL is operator-managed, not bundled
**Decision.** The app is a PostgreSQL client. It requires an existing server of major version 18,
connects on loopback, and never installs, starts, stops, or upgrades the server. A dedicated
`docvault_app` role has no superuser and no `CREATEDB`. The role password is encrypted with DPAPI
machine scope (Windows) and stored in the OS config folder.
**Rejected.** Bundling and managing a private cluster, as originally planned. It removes a
prerequisite, but it means shipping PostgreSQL binaries for every platform, owning its security
patches, and running a second service lifecycle inside the installer. It also duplicated
something the host already had.
**Rejected.** Supporting majors 16–18. Three majors triples the restore drill for a single
production host that already runs 18.
**Consequence.** The vault stops being fully self-contained for restore: a supported PostgreSQL
and a role must exist before the folder can be used. That is now an explicit step in the runbook
and the DR drill (`08` §4 and `08` §11). PostgreSQL patching moves to the operator, so the app can no
longer promise a 7-day patch window for the server. `docvault doctor` reports the gap instead.

### ADR-032 — Database dumps are encrypted
**Decision.** Write dumps as `DVD1` containers encrypted under
`dump_key = HKDF(VMK, "docvault/v1/dump")`, with a per-chunk GCM tag that covers the header, the
chunk index, and a final-chunk flag.
**Rejected.** Leaving the dump as plain `pg_dump` output. Encrypted columns mean document content
is still protected, but the structural columns travel in clear: dates, statuses, blob addresses,
the ACL graph, usernames, and password hashes. A stolen vault folder would then reveal the shape
of the practice without any passphrase, which contradicts the threat-model claim that the folder
holds only ciphertext.
**Rejected.** Compressing and encrypting the whole file in one GCM operation. It requires the
whole dump in memory or a second pass, and it gives no incremental truncation detection.
**Rejected.** Encrypting the audit log the same way. The audit chain must be verifiable and the
unlock-denial events are written before the vault opens. The log's contents are documented as a
known, accepted leak instead.
**Consequence.** Restore needs the vault key before it can read the dump, which is no regression
because the key was already required for every blob. A transient plaintext dump exists in
`vault/tmp/` during a restore and is deleted in a `finally`. `docvault dump-list` exists so
diagnostics do not require a full restore.

### ADR-033 — Previews are allowed; renditions are encrypted and disposable
**Decision.** A user with `read` can see a document rendered on screen. Rendered pages are cached
as ordinary `DVC1` blobs, content-addressed, encrypted under the same envelope, listed in
`renditions`, and deletable at any time. This supersedes the "no previews or thumbnails" half of
ADR-020.
**Rejected.** Keeping the original rule, which would have made the product unusable: you cannot
print what you cannot see. Also rejected: a plaintext cache directory, which would quietly undo
the entire encryption design for the sake of speed.
**Rejected.** Rendering in the browser from downloaded bytes. It would put decoding in the
client, make preview and print diverge, and still require the same `read` permission.
**Consequence.** The system now parses untrusted images and PDFs, which is a new and significant
attack surface (R-12). Preview is treated as a read everywhere in the permission model
(`06` §6). Disk usage grows with a cache that must be bounded and evicted (`08` §9.1).

### ADR-034 — `print` is a capability of its own, bit 32
**Decision.** Printing requires `print` on every document in the job. `print` implies `read`,
`read` implies `view`, and denies close downward.
**Rejected.** Free printing with `read`. Paper is the one copy the system cannot recall, so the
office needs a way to say "look, but do not copy".
**Consequence.** Defaults: editor and reader get `print`; auditor does not. The claim must be
stated honestly: anyone with `read` can download and print elsewhere. `print` is a policy
control, a workflow gate, and an audit hook — never a boundary (`01` R-11).

### ADR-035 — Printing is client-side; the server builds a PDF and stores nothing
**Decision.** `POST /print-jobs` validates the request, writes the job record, composes a PDF in
the render worker, and streams it. The user prints it from their own browser to their own printer.
**Rejected.** Sending the job to the host's spooler. It requires host-to-printer reachability for
every printer in the building, a much larger surface, and it puts the paper in the wrong room.
**Rejected.** Storing the generated PDF as a blob. It would be a new plaintext artifact — the
exact thing the design otherwise avoids — and it would need its own retention and purge story.
**Rejected.** Building the PDF in the browser. Preview and output would drift, and the layout
logic would be duplicated in two languages.
**Consequence.** The app cannot set duplex, paper tray, or scaling. The dialog tells the user what
to choose (`11` §10) and the PDF is built so the defaults are correct. A printout cannot be
recreated byte for byte after a recipe change; the job records the recipe hash instead.

### ADR-036 — Edits are a render recipe, not a version
**Decision.** Rotate, straighten, crop, brightness, contrast, gamma, grayscale, invert, threshold,
despeckle, and auto-trim are stored per version in `version_render_settings`. The stored bytes
never change, and changing the recipe never creates a version.
**Rejected.** Creating a version per adjustment. It produces a history of near-identical files,
makes "which one is the record" ambiguous, and spends the audit log on noise.
**Rejected.** Destructive editing of the stored blob. The record must stay as it arrived; a bad
threshold would otherwise be unrecoverable.
**Rejected.** Redaction as a recipe. A rectangle drawn over pixels is not redaction — the data is
still underneath and still in the cache. Real redaction destroys bytes, which is a different
feature with a different story, and is out of scope.
**Consequence.** A printout produced before a recipe change cannot be reproduced exactly. The
print job stores the recipe hash, so the difference is provable rather than invisible. Editing
requires `write`, because it changes what everyone sees and prints.

### ADR-037 — Front and back are separate documents
**Decision.** `pan_card_front` and `pan_card_back` are two document types, two documents, two
ACLs. `doc_types.side` may carry `front` or `back` as a sorting hint for a pre-filled print
queue. Nothing validates that a front has a back.
**Rejected.** A pairing model with a foreign key between halves. It forces every document into a
two-sided shape, needs its own permissions story, and breaks for a three-page deed.
**Rejected.** Automatic adjacency at print time. The app does not invent order (`12` §2).
**Consequence.** Printing a card's two sides is "select both, 1-up duplex". The user is in control
of order, which is how they already think about it.

### ADR-038 — Office files are intake-only, converted once to PDF
**Decision.** DOC, DOCX, and ODT are accepted on upload. The render worker converts them to PDF
once, under a 60-second cap, and the PDF is stored as an immutable blob referenced by
`document_versions.derived_pdf_addr`. All preview, editing, and printing use the PDF. The original
is retained and downloadable.
**Rejected.** Refusing Office files. Users have real agreements and letters in Word, and forcing
a manual "Save as PDF" step before every upload is friction the office will route around.
**Rejected.** Rendering Office on demand at preview or print time. A newer LibreOffice could
render a different page than the one printed last year, which is unacceptable for a record.
**Rejected.** An online document server such as Collabora. It adds a network service, an editing
surface, and a second permission model.
**Rejected.** XLSX and ODS. Print areas, scaling, page breaks, and hidden sheets make the printed
result machine-dependent. Convert to PDF at capture.
**Consequence.** LibreOffice is a large, optional, ingest-only dependency (`02` §6.4, `08` §9.2).
When it is absent, Office uploads fail with `415` and a message naming the converter. Conversion
fidelity depends on installed fonts, so the PDF — not the DOCX — is the artifact of record, and
the difference is visible to the user at upload time.

### ADR-039 — The render worker is a separate process with no key material
**Decision.** Decoding runs in a worker started as a child process, communicating over pipes. It
receives plaintext bytes and a recipe, and returns pixels or PDF bytes. It has no vault key, no
database credentials, and no network. It has a 512 MB memory ceiling and a hard timeout, and it is
killed and restarted on violation.
**Rejected.** Decoding in the API process. A decoder zero-day would then reach the vault key,
which is the single most valuable thing in the system.
**Rejected.** A thread pool. Threads share the address space, so a memory ceiling cannot be
enforced and a crash takes the API with it.
**Consequence.** One plaintext copy crosses a process boundary, which is a deliberate and
documented trade (`01` R-12). Rendering costs a process start on the first request after idle,
which `02` §6.4 accepts. The worker is a second entry point to package and test.

### ADR-040 — Categories are a two-level `doc_types` tree, not folders
**Decision.** Classification uses one table, `doc_types`, at exactly two levels. A row with
`parent_id IS NULL` is a category; a row with a parent is a document type. Every document has
exactly one `doc_type_id`, so its category is derived and can never disagree with its type. Eight
categories are seeded, with roughly seventy types under them (`13` §4). A trigger enforces the
two-level limit.
**Rejected.** A separate `doc_categories` table. It would duplicate the parent row, its name
encryption, its seed script, and its join, to express something the parent row already expresses.
**Rejected.** A folder tree. Folders need their own inheritance rules on top of entity and
document ACLs, and two inheritance systems produce permissions that nobody can explain (ADR-016).
**Rejected.** Free-form category text. Two spellings of "Property" means two filters and two
counts.
**Consequence.** Adding a category is an admin action, not a user one. A document is always
findable through one path, which is what makes the filter rail and the entity packet order
predictable (`12` §10). The cost is that an unusual document must pick an existing type or an
admin must add one.

### ADR-041 — Sensitivity changes policy, never storage
**Decision.** `confidentiality` is one of `normal`, `sensitive`, or `restricted`. It is copied
from the type's default at upload, may be raised by anyone holding `write`, and may be lowered
only by an admin. It changes printing, badges, audit detail, and purge, and it changes nothing
about how bytes are stored. `restricted` requires an explicit per-document `print` grant, admin
exemption aside (`13` §6).
**Rejected.** A plaintext tier for documents that "need" to stay unencrypted — for example so
that another program can read them. This was an explicit requirement to avoid: sensitive
documents must not sit on disk as readable files. A second storage path would double the code,
double the write rules, and become the one place a leak happens (`01` R-1).
**Rejected.** Sensitivity as an ACL role. It is a property of the paper, not of the person.
**Consequence.** Encryption is uniform and auditable: every blob, rendition, and derived PDF is
ciphertext. The cost is that "unencrypted" is not available even when convenient, and that
`restricted` documents need one extra sharing step before printing.

### ADR-042 — TIFF is not an accepted format
**Decision.** Accepted input is JPEG, PNG, PDF, plus DOC/DOCX/ODT intake. TIFF is refused with
`415`, the same as any other unsupported type.
**Rejected.** Keeping TIFF for bilevel and multi-page scans. PDF handles both, the browser cannot
display TIFF without a decoder, and the print composer would need a re-encode step for it.
**Consequence.** One less decoder in the render worker, which is the largest attack surface in the
system (ADR-039). A scanner must be configured to emit PDF or JPEG/PNG. Any existing TIFF scan is
converted once, outside the app, before upload (`08` §10).

### ADR-043 — Development runs the same PostgreSQL major and code paths as production
**Decision.** A development machine runs PostgreSQL 18, the same `citext`, `jsonb`, triggers, and
partial indexes as the office. It uses a disposable cluster on port 5433 and a disposable vault
under `var/`, but it does not substitute a different database, a mocked repository, or a container
that hides filesystem behaviour. Schema and permission tests run against the real thing.
**Rejected.** SQLite for convenience. Half the schema would not exist, `jsonb` queries would be
different, and a passing test would prove nothing about the code that ships (`14` §2).
**Rejected.** A shared development database on the office server. It mixes test data with records,
exposes PostgreSQL beyond loopback, and makes a destructive test everyone's problem.
**Rejected.** Docker Compose as the default development path. The production platform is Windows
with a native filesystem, and the vault's correctness depends on atomic rename and fsync
(`03` §7). A container hides exactly the behaviour worth testing.
**Consequence.** Setup is heavier than `pip install` plus SQLite: a developer installs PostgreSQL
and creates one cluster (`14` §4.3). In exchange, the first place a schema bug appears is the
developer's machine, not the office. The development vault is explicitly disposable and must never
hold production data.

---

## 3. Ideas we considered and dropped

| Idea | Why it was dropped |
|---|---|
| Event-sourced journal as the main store | Unnecessary once the dump ships inside the vault (ADR-002) |
| Crypto-shredding through document keys | Conflicts with self-contained blobs (ADR-011). Reversible if you accept depending on the database. |
| De-duplication | Leaks equality between entities (ADR-012) |
| Per-user keys in v1 | Escrow and recovery costs; documented as a future path (ADR-017) |
| Full-text search | Needs plaintext copies of documents (ADR-020) |
| Several vaults per install | Every recovery, backup, and lock rule doubles. One vault is enough. |
| SQLite instead of PostgreSQL | Contradicts the stated stack and has a weaker concurrency story |
| Docker for everything | Filesystem behaviour on Windows and macOS breaks the integrity model (ADR-021) |
| Bundling the PostgreSQL server | Extra binaries, extra patching, a second service lifecycle, for a host that already has a server (ADR-031) |
| An unencrypted dump | Leaks the ACL graph, dates, and usernames to anyone holding the folder (ADR-032) |
| A folder tree for documents | Inheritance complexity with no records-management benefit |
| Field-level permissions | Harder to explain than it protects. The document is the unit of sensitivity. |
| macOS support in v1 | Untested hardware and filesystem behaviour; the format stays neutral so it can be added later (ADR-021) |
| A plaintext preview or thumbnail cache | It would undo the encryption design for the sake of a few milliseconds (ADR-033) |
| Rendering Office files at preview or print time | A newer converter could print a different page than last year's record (ADR-038) |
| Storing the generated print PDF | A new plaintext artifact, with its own retention and purge problem, for no benefit (ADR-035) |
| Sending jobs to the host's printer spooler | It puts paper in the wrong room and needs host-to-printer reachability (ADR-035) |
| Redaction as a render recipe | A rectangle over pixels is not redaction; the bytes are still there (ADR-036) |
| A pairing model for front and back | Forcing every document into a two-sided shape breaks a three-page deed (ADR-037) |
| Auto-layout by document type | The app would be inventing rules the user did not ask for (`12` §13) |
| Building the print PDF in the browser | One renderer, not two, or preview and output drift (ADR-035) |
| A separate `doc_categories` table | The parent row of the two-level type tree already is the category (ADR-040) |
| Folders for documents | Two inheritance systems, for a navigation gain the category already gives (ADR-040) |
| An "unencrypted" tier for sensitive documents | Every document stays ciphertext; sensitivity changes policy only (ADR-041) |
| Accepting TIFF | PDF covers multi-page and bilevel; each extra decoder is attack surface (ADR-042) |
| Automatic classification by document content | Needs OCR and a guess; a wrong guess about a share certificate is worse than a click (`13` §10) |
| SQLite or a mocked repository for development | It would test a different schema and hide filesystem bugs (ADR-043) |
| Running development against the office database | It mixes synthetic and real data, and widens database exposure (ADR-043) |

---

## 4. Open questions for the product owner

These have sensible defaults, but the answer changes the design.

| # | Question | Default if you do not answer |
|---|---|---|
| O-1 | Real volumes: how many entities, documents, and users? | The envelope in `00` §6 |
| O-2 | Who are the passphrase custodians? | Two people, plus a sealed physical copy |
| O-3 | What backup schedule and off-site policy? | Nightly dump, weekly copy, monthly off-site |
| O-4 | Is purge required at all, or is archive-only enough? | Purge available to admins |
| O-5 | Are documents ever linked to more than one entity in practice? | Supported, using union of allows |
| O-6 | Does any external party ever need access? | No. Local network only. |
| O-7 | Retention periods per document type | NULL, meaning keep indefinitely, until supplied |
| O-8 | **Is Office intake on by default?** It requires installing and patching LibreOffice on the host. | On if the installer detects LibreOffice, off otherwise |
| O-9 | **What is the real print workload?** Pages per job, jobs per day, sheets per month. | 500 pages per job, 5 GB rendition ceiling |
| O-10 | **What is the default print layout?** Simplex A4 or 2-up duplex? | 2-up duplex, 5 mm margins |
| O-11 | **Do reader and editor get `print` by default**, or is it granted per document? | Granted by default, since they could download and print anyway |
| O-12 | **Is `print` ever granted without `read`?** The model expands it, so the answer is effectively no. | `print` always implies `read` |
| O-13 | **Is "explicit `print` grant" the right default for `restricted` documents**, or is it too much friction for a two-person office? | Explicit grant, admin exempt (`13` §6) |

O-8 and O-11 are the two that change what ships in the first build. O-13 changes how much
friction a restricted document carries. The rest change defaults and numbers, not structure.
