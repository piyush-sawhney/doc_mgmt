# DocVault — Documentation

Design documentation for an offline, encrypted document management application for a small
office. **No code exists yet.** These documents are the specification.

New to the project? Read [the glossary](glossary.md) first. It defines every technical word in
plain language and takes about ten minutes.

---

## Reading order

Pick the row that matches why you are here.

| If you are… | Read in this order |
|---|---|
| **The product owner** | `00` → `01` → `13` §4 → `10` §4 (open questions) |
| **Reviewing the storage design** | `03` → `05` → `04` |
| **Building the backend** | `02` → `03` → `04` → `05` → `06` → `07` → `13` |
| **Building the frontend** | `11` → `13` → `07` → `06` → `09` §14 |
| **Building the printer** | `12` → `11` §9–10 → `13` §6 → `06` §2 |
| **Running it day to day** | `08` → `03` §13 and `03` §14 |
| **Checking the security claims** | `01` → `05` §7 → `06` §10–11 |
| **Choosing a version to install** | `02` §6.1–6.3 |

## Documents

| # | Document | The question it answers |
|---|---|---|
| — | [Glossary](glossary.md) | "What does this word mean?" |
| 00 | [Overview](00-overview.md) | What are we building, for whom, and what is out of scope? |
| 01 | [Threat Model](01-threat-model.md) | What do we defend against — and what do we openly not? |
| 02 | [Architecture](02-architecture.md) | How do the pieces fit together, and which versions are pinned? |
| 03 | [Vault Format](03-vault-format.md) | **The compatibility contract.** Exactly what is on disk. |
| 04 | [Data Model](04-data-model.md) | Which tables exist, what they hold, and what the database enforces. |
| 05 | [Cryptography](05-crypto.md) | How content is encrypted, and what that does not protect. |
| 06 | [Roles and Access Control](06-rbac-acl.md) | Who can see and do what, and how the decision is made. |
| 07 | [API](07-api.md) | What the endpoints look like and how clients should behave. |
| 08 | [Operations](08-ops.md) | How to install, back up, restore, verify, and recover. |
| 09 | [Key Flows](09-flows.md) | What happens step by step, including when things fail. |
| 10 | [Decisions](10-decisions.md) | Why each choice was made, what was rejected, and what it costs to change. |
| 11 | [Frontend and Viewer](11-frontend.md) | What every screen does, and what a clerk can reach from the browser. |
| 12 | [Printing](12-printing.md) | How a selection becomes sheets: grids, duplex, paper, page ranges, audit. |
| 13 | [Classification](13-classification.md) | Which category and type a document goes in, and what sensitivity changes. |

## The three contracts

A change that conflicts with one of these is either wrong or needs a version bump.

1. **`03-vault-format.md`** — what is on disk. The vault must stay readable by future versions
   and restorable on future hardware.
2. **`04-data-model.md`** — the database schema. Changes go through Alembic and a
   pre-migration dump.
3. **`07-api.md`** — the client contract. Additions are allowed within `v1`; breaking changes
   need `v2`.

Every other document can be improved cheaply.

## The system in five sentences

1. One folder on disk is the whole backup. Copy it, then restore the encrypted database dump that
   sits inside it. PostgreSQL itself is installed by the operator and is not part of the folder.
2. Every document version has its own random key, and that key is wrapped by a vault key derived
   from the passphrase.
3. Metadata is encrypted in the database. Exact lookups use keyed fingerprints called blind
   indexes.
4. Permissions are enforced by one check inside the application, not by cryptography.
5. Nothing is permanently removed except by an admin, with a reason, and the audit log records
   it.

## Terms of art used in these documents

| Word | What it means here |
|---|---|
| **Must / must not** | A contract. Breaking it is a defect, not a preference. |
| **Should** | The normal choice. Deviating needs a note in `10-decisions.md`. |
| **May** | Genuinely optional. |
| **In plain words** | A short explanation at the top of each document. Read these first. |
| **`06` §5** | Document 06, section 5. Section numbers are stable and safe to cite. |
| **ADR-0xx** | A decision record in `10-decisions.md`. |

Diagrams are Mermaid; they render on GitHub, GitLab, and in most editors. Code blocks are
illustrative sketches, not the implementation.

## Changing the design

1. Work out which contract the change touches: `03`, `04`, or `07`.
2. Add an ADR to `10-decisions.md` **before** writing code, including what you rejected.
3. Update every document that repeats the affected rule. These files repeat important rules on
   purpose, so stale copies are the main risk.
4. If bytes on disk or database columns change, write down the migration and add a test.

## Status

| Area | State |
|---|---|
| Design documents | **Final v1**, committed 2026-10-28. Ready to build from. |
| Vault format | Frozen for v1, awaiting sign-off |
| Threat model | Needs the product owner to confirm the T2 boundary (`01` §3) |
| Code | Not started |
| Open questions | 13 questions with working defaults in `10-decisions.md` §4 |

Two things are deliberately still open, and neither blocks the start of coding:

1. **The T2 boundary** — the threat model assumes an attacker who can read the disk but not
   administer the running host. If that is wrong, the design changes.
2. **Version pins for the media libraries** — Pillow, pypdfium2, pypdf, and LibreOffice are pinned
   at first install (`02` §6.1), because their release cadence is not known in advance.

Everything else has a default. If the product owner answers nothing, the defaults in `10` §4 are
what gets built.
