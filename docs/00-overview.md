# 00 — Overview

> **In plain words:** We are building a private filing cabinet for a small office. It runs on
> one desktop computer. Staff open it in a browser on the office network. Every file is
> encrypted on disk, and the whole system lives in one folder so it can be backed up by copying
> that folder.
>
> **Read this first.** Then read `01-threat-model.md` and `03-vault-format.md`.

| | |
|---|---|
| **Document status** | Draft v1, before implementation |
| **Last updated** | 2026-10-28 |
| **Who should read it** | The product owner, implementers, and whoever maintains the system later |

---

## 1. What we are building

A secure place to keep documents that belong to **entities** — people and organisations — with
tight control over who may read, change, or delete each document.

The defining feature is **portability**. The whole installation is one folder on disk. Copy
that folder, restore the database dump that lives inside it, and the application carries on as
if nothing happened. It does not matter that the computer is new.

> **One vault folder = one complete backup.**

Almost every design choice in these documents follows from that one sentence.

## 2. Scope

### What v1 includes

- An **entity register** for individuals and organisations (company, LLP, trust, HUF,
  partnership, society, government, other).
- **Multiple identifiers per entity**: PAN, Aadhaar, GSTIN, CIN, DIN, passport, and so on.
- **Documents** linked to one or more entities, with a role for each link.
- **Immutable versions**: an upload is never overwritten.
- An admin-managed **document type list**, tags, and issue/expiry dates.
- **Classification on two levels**: eight categories — identity, property, legal, corporate,
  financial, employment, insurance, other — each holding specific types such as PAN card, sale
  deed, or share certificate. Every type carries a default **sensitivity** of `normal`,
  `sensitive`, or `restricted` (`13`).
- **Users, groups, roles**, and per-entity and per-document permissions.
- A **tamper-evident audit log**.
- **Vault operations**: create, back up, restore, verify, salvage.
- **Access from other computers** on the local network, over HTTPS.
- **On-screen preview** of every allowed format, with page navigation and zoom.
- **Non-destructive cleanup**: rotate, crop, straighten, brightness, contrast, grayscale,
  threshold. Stored as a render recipe, not as a new version.
- **Printing**: select any number of documents, order them, place 1, 2, 4, 6 or 9 on a side,
  simplex or duplex, on the paper size you choose. The server builds a print-ready PDF, the user
  prints it at their own desk.
- **`print` as a permission of its own**, separate from `read`.

Allowed formats are **JPEG, PNG and PDF**, plus **DOC, DOCX and ODT** as intake formats that are
converted once to PDF at upload (`10` ADR-038). JPEG and PNG cover scans and photographs; PDF is
the format for anything multi-page, and the one to use when a document arrives as several images.
TIFF is deliberately not accepted (`10` ADR-042): PDF already covers multi-page and bilevel scans,
and every TIFF removed is a decoder removed from the attack surface.

### What v1 leaves out

| Excluded | Why |
|---|---|
| Text extraction, OCR, full-text search | They need a plaintext copy of every document. v1 searches metadata only. |
| Redaction | A black box drawn in the browser is not redaction. It needs new bytes and a destroyed original, which is a different feature. |
| Merging documents, auto-grouping, auto-pairing | The app does not invent structure. Composition stops at the print grid (`12` §2). |
| Driving the printer or the spooler | The user prints at their desk. The app produces a PDF and stops (`12` §1). |
| Stored print files | A second plaintext artifact to purge, for no benefit. |
| Spreadsheet printing from XLSX/ODS | Print areas and scaling differ per machine. Convert to PDF at capture. |
| Editing Office files | Store and print them, never edit them. |
| Expiry reminders and notifications | Expiry *dates* are stored; alerts come later. |
| Relationship graphs for directors and guarantors | The tables exist; the screen does not. |
| Workflows, approvals, e-signature | Not needed to prove the core product. |
| Internet exposure | Local network only, never hosted. |
| Shareable external links | Everything is controlled inside the office network. |
| Per-user encryption keys | Permissions are enforced by the app; see `05-crypto.md` §12. |

> **Rule of thumb, revised.** The old rule was "if a feature needs a readable copy of a document
> to work, it waits". That rule cannot survive a viewer and a printer, and pretending otherwise
> would just hide the decision. The rule that replaces it: **a readable copy may exist inside a
> running process, and never on disk in the clear.** Renditions are encrypted, print output is
> never stored, and the temporary files in `vault/tmp/` stay the only plaintext window in the
> system.

## 3. Who uses it

| Person | Role | What they do |
|---|---|---|
| **Office admin** | Admin | Creates users, manages the vault, purges, handles recovery |
| **Records clerk** | Editor | Registers entities, uploads documents, adds versions |
| **Reviewer or partner** | Reader | Looks up entities and reads or downloads documents |
| **Auditor** | Auditor | Checks who did what; sees metadata and the audit trail, not content |
| **Vault custodian** | — | Holds the passphrase; often the same person as the admin |

Plan for **1 to 20 users**, all known by name, on one trusted office network. There is no
anonymous access and nobody can sign themselves up.

## 4. Core ideas

Short definitions are below. The full list, with every technical term, is in
[`glossary.md`](glossary.md).

| Term | Meaning |
|---|---|
| **Vault** | The folder on disk that holds all encrypted content, the database dump, the audit log, and the wrapped key. It is the unit of backup. |
| **Entity** | The subject that documents belong to. Either a person (`individual`) or an organisation. |
| **Person** | A natural person record. Used for individuals, and for directors, signatories, and guarantors of organisations. |
| **Identifier** | A typed ID value attached to an entity, such as a PAN or GSTIN. Stored as a row, never as a column. |
| **Document** | A logical document: title, type, dates, owner, permissions. It is a container for versions. |
| **Version** | One uploaded file. Its content is encrypted and addressed by content. |
| **Blob** | The encrypted bytes on disk for one version. Never named after the user's file. |
| **ACL** | The list saying who may do what to a document. Inherits from the entity by default. |
| **Manifest** | `manifest.json` at the vault root: identity, format version, key fingerprint. |
| **KEK / VMK** | The key that encrypts other keys / the vault master key. See `05-crypto.md`. |
| **Break-glass** | An admin's audited, reason-required access to content they were not granted. |

## 5. What makes it different

**Portable by design.** The database stores no absolute paths except one re-pointable
`vault_root` setting. Blob names are content hashes. The encrypted database dump ships inside the
vault. Moving to new hardware is a written, rehearsed procedure, not an adventure.

**Encrypted at rest, with honest limits.** Every version is encrypted with AES-256-GCM under its
own key. That key is wrapped by a key derived from the passphrase. The documents say plainly what
this protects against. They also state the limit: an admin who holds the passphrase can read
everything.

**History that cannot be rewritten.** Versions are never overwritten. "Delete" is reversible.
"Purge" is restricted and audited.

**Small enough to understand.** One backend process, one PostgreSQL instance, one React app.
No message queues, no object storage, no cloud services.

## 6. Size and load we are designing for

| Measure | v1 target | Where it breaks down |
|---|---|---|
| Users | 1–20 | Hundreds, which needs a real identity provider |
| Entities | up to about 25,000 | Around a million, which needs partitioning |
| Documents | up to about 200,000 | Around a million |
| Versions (blobs) | up to about 1,000,000 | Several million, which needs deeper folder fan-out |
| Largest file | 100 MB, configurable | — |
| Vault size | up to about 1 TB | Depends on how long the verify job takes |
| Concurrent clients | 1–10 | Tens, which is fine, but session cleanup starts to matter |

> If your real numbers are far outside these, say so before coding. Indexing, permission
> queries, and the verify job all change.

## 7. Platform commitments

- **Production host:** Windows. **Development host:** Linux. Both are tested in v1.
- **macOS:** not tested in v1. The vault format is OS-neutral, so it can be added later without a
  format change, but an untested platform is not a supported platform.
- **Backend:** Python 3.14, FastAPI 0.162, SQLAlchemy 2.1, Alembic 1.20, psycopg 3.3.
- **Database:** PostgreSQL 18.6, installed and patched by the operator. The app is a client only,
  and refuses any other major version.
- **Frontend:** React 19.3, TypeScript 7.0, Vite 8.3, built on Node 24 LTS.
- **Packaging:** one installer per supported OS. PostgreSQL is a prerequisite, not bundled.
- **Network:** HTTPS on the local network only. No outbound calls and no telemetry.

Exact versions, release dates, and the reason for each choice are in `02-architecture.md` §6.1.
The update rules are in `02-architecture.md` §6.2, and the database prerequisite in
`02-architecture.md` §6.3. Two choices are deliberately **not** the newest available:

- **Python 3.14 rather than 3.15.** 3.15 is only weeks old, and packaging tools and prebuilt
  libraries lag behind a new minor release.
- **PostgreSQL 18 rather than 19.** Version 19 exists only as a release candidate, and a
  records database should not run on one.

Both are reviewed under the update policy, so they will not be forgotten.

## 8. Assumptions to confirm

These are defaults chosen so the documents could be written. Confirm or change them.

| # | Assumption | Default |
|---|---|---|
| A1 | One vault per installation | Single vault |
| A2 | Who holds the passphrase | Two custodians, plus one sealed copy in a physical safe |
| A3 | Backup routine | Nightly database dump into the vault; folder copied to external media weekly |
| A4 | Allowed file types | PDF, images, Office files, text, CSV, ZIP. Executables and scripts blocked. |
| A5 | Delete model | Editors soft-delete; admins purge; legal hold blocks purge |
| A6 | Document numbering | None in v1. Documents are identified by an ID and a title. |
| A7 | Time zone | Store UTC, display the host's local time |
| A8 | Language | English interface, UTF-8 everywhere, Unicode names supported |

## 9. How to read this documentation

Each document stands alone, but assumes the ones before it.

| Your question | Read |
|---|---|
| What are we defending against? | `01-threat-model.md` |
| How do the pieces fit together? | `02-architecture.md` |
| What exactly is on disk? What can I never change? | `03-vault-format.md` |
| Which tables exist and what do they hold? | `04-data-model.md` |
| How is content encrypted, and what can it not protect? | `05-crypto.md` |
| Who can see what? | `06-rbac-acl.md` |
| What does the API look like? | `07-api.md` |
| How do I install, back up, restore, and verify? | `08-ops.md` |
| What happens when I click upload? | `09-flows.md` |
| Why was this decided this way? | `10-decisions.md` |
| Where does this document go, and how sensitive is it? | `13-classification.md` |

**The contracts, in priority order:** `03-vault-format.md` (on-disk compatibility), then
`04-data-model.md` (schema), then `07-api.md` (client compatibility). Everything else can change
without breaking users.

## 10. What "done" means for v1

1. A vault can be created, filled, backed up, moved to another machine, and restored. A written
   drill proves this on Windows and Linux.
2. Every document byte, every rendition, and every database dump on disk is encrypted. No
   readable copy exists anywhere outside a running process.
3. Permissions are enforced in one shared place, and tests attempt every list, search, count,
   export, download, preview, and print route as an unauthorised user.
4. The audit log can detect any edit or deletion of its own history.
5. A reader on another machine can log in, find a document by metadata, and download it over
   HTTPS — and cannot reach a document they lack permission for by any route.
6. A clerk can select forty documents, arrange them 4-up duplex on A4, print the result, and
   never open Word. The generated PDF is not stored, and the job appears in the audit log.
7. A user with `read` but not `print` can open a document and cannot add it to a print job.
8. Every screen in `11` exists, and `Ctrl+P` opens the print dialog rather than the browser's.
9. Every document carries a type, its category is derived from that type, and a `restricted`
   document cannot be printed without an explicit grant (`13` §6, §11).
