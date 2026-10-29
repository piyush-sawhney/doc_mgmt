# 07 — API Specification

> **In plain words:** The browser talks to the backend over HTTPS using ordinary JSON. This
> document lists the endpoints, the shape of requests and responses, the error format, and the
> rules every client must follow.
>
> **Read this if:** you are building the frontend, writing a script against the API, or testing
> that the endpoints behave.

| | |
|---|---|
| **Base path** | `/api/v1` |
| **Content type** | `application/json`, except uploads and downloads |
| **Errors** | `application/problem+json` |
| **Authentication** | Session cookie plus a CSRF header |
| **Versioning** | Path prefix. Additions only within `v1`. |

FastAPI generates an OpenAPI document from the code. That generated document is the
machine-readable truth; this file describes the intent it must satisfy.

---

## 1. Conventions

| Topic | Rule |
|---|---|
| IDs | UUIDv7 strings, opaque to clients |
| Timestamps | ISO-8601 UTC with `Z`, for example `2026-10-28T11:04:19.221Z` |
| Dates | `YYYY-MM-DD` |
| Field names | `snake_case` |
| Nulls | Send an explicit `null`. On PATCH, an omitted field means "unchanged". |
| Pagination | Cursor-based. `limit` is 1–100 (default 25). Responses carry `next_cursor`. |
| Sorting | `sort=created_at:desc`, with an allow-list of fields |
| Booleans | Real JSON booleans, never `"true"` |
| Unknown fields | Rejected with `422`, which catches typos early |
| Retries | Send `Idempotency-Key` on every POST that creates or uploads |
| Concurrency | Every resource has an `ETag`. PATCH and DELETE **require** `If-Match`; `428` if missing. |
| Tracing | `X-Request-Id` is echoed, and generated if absent |

### 1.1 Error format

Every error looks like this:

```json
{
  "type": "https://docvault.local/problems/version-conflict",
  "title": "Version conflict",
  "status": 409,
  "detail": "The document was modified by someone else. Reload and retry.",
  "instance": "/api/v1/documents/0192f0c9-...",
  "request_id": "01J9Z3K4T7",
  "errors": [{ "field": "title", "code": "too_long", "message": "Maximum 200 characters" }]
}
```

| Status | When it is used |
|---:|---|
| `400` | Malformed request: bad JSON or a bad UUID |
| `401` | No session, or the session expired |
| `403` | Logged in and allowed to view, but lacking the specific capability |
| `404` | Not found, **or not visible**. Existence is not revealed. |
| `409` | Optimistic-lock conflict, duplicate username, a version-number race, or deleting a document type that is still in use |
| `410` | Download ticket expired or already used |
| `413` | Upload exceeds `max_file_bytes` |
| `415` | File type not allowed |
| `422` | Validation failed; field details are in `errors` |
| `423` | Vault is locked or not unlocked |
| `428` | `If-Match` is required |
| `429` | Throttled. `Retry-After` is present. |
| `500` | Unexpected error. Correlation ID only, never a stack trace. |
| `503` | Database or vault unavailable |
| `504` | A render or print job exceeded its time budget |
| `507` | Not enough storage, or the render worker hit its memory ceiling |

## 2. Authentication

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/login` | `{username, password}` sets `dv_session` and returns `{user, csrf_token, totp_required}` |
| `POST` | `/auth/totp/verify` | `{code}` completes a login that needs a second factor |
| `POST` | `/auth/logout` | Revokes the session |
| `GET` | `/auth/session` | Current user, roles, capabilities, and CSRF token |
| `POST` | `/auth/password` | `{current_password, new_password}` and revokes all other sessions |
| `POST` | `/auth/totp/enroll` | Returns a provisioning URI and secret, once |
| `POST` | `/auth/totp/confirm` | `{code}` turns TOTP on |
| `POST` | `/auth/totp/disable` | `{password}` turns TOTP off |

Rules:

- The cookie is `dv_session`, with `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`, and an
  opaque 32-byte token.
- Every request that changes state must send `X-CSRF-Token` matching the session's secret.
- Login throttle: 5 failures per 5 minutes per username **and** per IP, then `429` with a
  back-off. A successful login resets the counter.
- A password change or an admin disable revokes every session for that user immediately.
- `/auth/login` is the only endpoint reachable without a session, apart from `/healthz`.

## 3. Users and groups (admin only)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/users` | Filter by `status`, `role`, `q` |
| `POST` | `/users` | Creates a user with a temporary password and `must_change_password` |
| `GET` `PATCH` | `/users/{id}` | PATCH changes display name, roles, or status |
| `POST` | `/users/{id}/reset-password` | Returns a one-time temporary password |
| `POST` | `/users/{id}/sessions/revoke` | Kills every session |
| `GET` `POST` | `/groups` | |
| `GET` `PATCH` `DELETE` | `/groups/{id}` | `DELETE` is refused for system groups |
| `PUT` | `/groups/{id}/members` | Replaces membership: `{user_ids: [...]}` |

Admins cannot delete themselves, remove their own last admin role, or disable the last active
admin. All three return `422` with an explanation.

## 4. Entities

| Method | Path | Capability needed |
|---|---|---|
| `GET` | `/entities` | `view`, filtered |
| `POST` | `/entities` | `write` |
| `GET` | `/entities/{id}` | `view` |
| `PATCH` | `/entities/{id}` | `write`, plus `If-Match` |
| `DELETE` | `/entities/{id}` | `delete` (soft) |
| `POST` | `/entities/{id}/restore` | `delete` |
| `GET` | `/entities/{id}/documents` | `view` on each document |
| `GET` | `/entities/{id}/timeline` | `view` |
| `GET` `POST` | `/entities/{id}/identifiers` | `write` |
| `GET` | `/identifiers/{id}/reveal` | `write`. Returns the full value and is audited as `identifier.reveal`. |
| `PATCH` `DELETE` | `/identifiers/{id}` | `write` / `delete` |
| `GET` `POST` | `/entities/{id}/persons` | `write` |
| `DELETE` | `/entities/{id}/persons/{person_id}/{role}` | `write` |
| `GET` `PUT` | `/entities/{id}/acl` | admin |
| `GET` | `/entities/{id}/effective-access` | admin |

Query parameters for `GET /entities`:

| Parameter | Example | Notes |
|---|---|---|
| `q` | `q=acme` | Matches the decrypted display or legal name. See the note below. |
| `type` | `type=company` | Repeatable |
| `status` | `status=active` | |
| `identifier` | `identifier=pan:ABCDE1234F` | Exact match through the blind index |
| `has_expiring_docs` | `true` | Within 30 days |
| `include_deleted` | `true` | Admin only |
| `sort` | `created_at:desc` | `created_at` or `updated_at` |
| `limit`, `cursor` | | |

> **Note on `q`.** Names are encrypted, so a general substring search is impossible without a
> plaintext index. In v1, `q` does an exact normalised blind-index lookup **plus an in-memory
> prefix scan over at most 2,000 decrypted names**. That is a bounded compromise for a small
> office. The cap is configurable, and the interface states the limitation.

### Creating an entity

```http
POST /api/v1/entities HTTP/1.1
Content-Type: application/json
X-CSRF-Token: ...
Idempotency-Key: 7f1c...

{
  "entity_type": "company",
  "legal_name": "Acme Holdings Private Limited",
  "display_name": "Acme Holdings",
  "incorporation_date": "2014-06-02",
  "registered_address": "12 MG Road, Bengaluru 560001",
  "identifiers": [
    { "id_type": "pan",  "value": "AABCA1234B" },
    { "id_type": "cin",  "value": "U74140KA2014PTC012345" },
    { "id_type": "gstin","value": "29AABCA1234B1Z5" }
  ],
  "notes": "Group holding company"
}
```

```http
HTTP/1.1 201 Created
ETag: W/"1"
Location: /api/v1/entities/0192f0c4-7a1e-7c3b-9a55-2c1f0b6d4e11

{
  "id": "0192f0c4-7a1e-7c3b-9a55-2c1f0b6d4e11",
  "entity_type": "company",
  "legal_name": "Acme Holdings Private Limited",
  "display_name": "Acme Holdings",
  "identifiers": [
    { "id": "...", "id_type": "pan", "value_masked": "AA******4B", "verified": false }
  ],
  "acl_mode": "inherit",
  "status": "active",
  "created_at": "2026-10-28T11:04:19.221Z",
  "updated_at": "2026-10-28T11:04:19.221Z"
}
```

**ID values are masked on read**, as `AA******4B`. Full values go only to users with `write` on
the entity, or through the audited `reveal` endpoint. This stops a reader from harvesting PANs
through list endpoints.

## 5. Documents

| Method | Path | Capability needed |
|---|---|---|
| `GET` | `/documents` | `view`, filtered |
| `POST` | `/documents` | `write`. Multipart; creates the document and version 1. |
| `GET` | `/documents/{id}` | `view` |
| `PATCH` | `/documents/{id}` | `write`, plus `If-Match` |
| `DELETE` | `/documents/{id}` | `delete` (soft) |
| `POST` | `/documents/{id}/restore` | `delete` |
| `POST` | `/documents/{id}/purge` | **Admin only**, body `{reason}`. The document must already be soft-deleted. |
| `GET` | `/documents/{id}/versions` | `view` |
| `POST` | `/documents/{id}/versions` | `write`. Multipart. |
| `GET` | `/documents/{id}/versions/{n}` | `view` |
| `POST` | `/documents/{id}/versions/{n}/download-ticket` | `read` |
| `GET` | `/documents/{id}/acl` | `manage_acl` |
| `PUT` | `/documents/{id}/acl` | `manage_acl`. Replaces all entries. |
| `GET` | `/documents/{id}/effective-access` | `manage_acl` |
| `POST` `DELETE` | `/documents/{id}/links` | `write` |
| `POST` `DELETE` | `/documents/{id}/tags` | `write` |

`GET /documents` accepts `entity_id`, `doc_type_id`, **`category`** (a category `code` such as
`property`), `confidentiality`, `status`, `from`, `to`, `q`, and paging parameters. `category` is
resolved through the type, so a filter on `property` returns every document whose type belongs to
that category, without a second stored column (`13` §3).
`q` is a case-insensitive substring match against decrypted titles after ACL and structured filters
have narrowed the candidate set. It scans at most 10,000 candidates and returns `413` if the search
would exceed that bound; callers can add filters and retry.

`PATCH /documents/{id}` may raise `confidentiality` with `write`. Lowering it is admin-only and
returns `422` with a field error otherwise, audited with the old and new level (`13` §6).

`POST /documents/{id}/versions` uses the same multipart `metadata` and `file` parts as the initial
upload. Its metadata accepts only an optional `note`; the document metadata is unchanged. Supply an
`Idempotency-Key`; an exact retry returns the original version response, while reusing the key with
different metadata or file content returns `409`.

Version responses include a stable version `id`; use it as `version_id` in a print-job request.
`GET /tags` lists decrypted tag names for an authenticated user; `POST /tags` creates or returns a
tag. Link and document-tag `POST`/`DELETE` routes require `write` plus `If-Match`, increment the
document ETag only when membership changes, and append audit events. Global `DELETE /tags/{id}` is
admin-only and detaches the tag from documents without deleting those documents.

`POST /documents/{id}/purge` is administrator-only and requires a reason of 10–500 characters.
The document must be soft-deleted, outside its `purge_after` retention window, and not under legal
hold. The operation overwrites and unlinks original, derived, and rendition blobs, invalidates
download tickets, removes rendition recipes/cache rows, and leaves document/version tombstones
with a `document.purge` audit event.

### 5.1 Uploading a document

```http
POST /api/v1/documents HTTP/1.1
Content-Type: multipart/form-data; boundary=...
X-CSRF-Token: ...
Idempotency-Key: 9a02...

--boundary
Content-Disposition: form-data; name="metadata"
Content-Type: application/json

{
  "title": "Board resolution — FY2025-26",
  "doc_type_code": "board_resolution",
  "entity_links": [{ "entity_id": "0192f0c4-...", "link_role": "belongs_to" }],
  "issue_date": "2026-04-12",
  "expiry_date": null,
  "confidentiality": "sensitive",
  "tags": ["fy2025-26"],
  "acl_mode": "inherit"
}

--boundary
Content-Disposition: form-data; name="file"; filename="resolution.pdf"
Content-Type: application/pdf

<binary>
--boundary--
```

What the server does, in order:

| Step | Rule |
|---|---|
| 1 | Check `write` on every linked entity **before** reading the body |
| 1a | Resolve `doc_type_code` to a type under a category. An unknown or disabled code is `422`. The type supplies the default sensitivity and the expiry requirement (`13` §7). |
| 1b | Resolve `confidentiality`: if omitted, copy the type default; if higher than the default, accept; if lower, `422` unless the caller is an admin. A supplied `doc_type_id` and `doc_type_code` that disagree is `422`. |
| 2 | Enforce `Content-Length ≤ max_file_bytes`. Otherwise stream and abort at the cap with `413`. |
| 3 | Sniff the MIME type from magic bytes. Reject executables and scripts with `415`, even if renamed. |
| 3a | Accept only `image/jpeg`, `image/png`, `application/pdf`, and — when a converter is configured — `application/msword`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `application/vnd.oasis.opendocument.text`. Anything else is `415` naming the accepted list. |
| 3b | Reject a PDF that declares JavaScript, launch actions, or embedded files, with `415` (`01` R-12). |
| 3c | For an Office file, convert to PDF in the render worker, capped at 60 s. Store the PDF as `derived_pdf_addr`. A conversion failure aborts the upload; nothing is stored. |
| 4 | Encrypt as it streams into `vault/tmp/*.part`. No plaintext temp file. |
| 5 | `fsync`, rename into `blobs/`, then start the database transaction |
| 6 | Return `201` with the document, version, and `ETag` |
| 7 | The same `Idempotency-Key` within 24 hours returns the original `201` body, not a duplicate |

The version object includes its stable `id` for use in render and print requests:
`"version": {"id": "0192...", "version_no": 1, "plaintext_size": 48213, "mime": "application/pdf", "derived_pdf": null}`.

An Office upload returns `201` only after the conversion succeeds, with
`"derived_pdf": {"pages": 4, "size": 118422}` in the version object, so the user can see that a
readable copy exists before they rely on it. If no executable Office converter is configured, the
upload is rejected with `415`; the original Office file is encrypted and retained alongside the
derived PDF when conversion succeeds.

### 5.2 Downloading a document

A download is two steps: ask for a ticket, then redeem it.

```http
POST /api/v1/documents/{id}/versions/2/download-ticket
```

```json
{ "url": "/api/v1/downloads/6c1f5a...", "expires_at": "2026-10-28T11:05:19Z", "filename": "resolution.pdf" }
```

```http
GET /api/v1/downloads/6c1f5a... HTTP/1.1
Cookie: dv_session=...
```

| Rule | Reason |
|---|---|
| Ticket lives 60 seconds and works once | A copied URL dies immediately |
| Ticket is bound to `user_id` and `source_ip` | A stolen ticket is useless elsewhere |
| The session is still required | Defence in depth, not a bearer-only URL |
| `Cache-Control: no-store`, `Content-Disposition: attachment` | No browser caching, no inline rendering |
| `Content-Type` comes from the stored sniffed MIME type | Prevents content-type confusion |
| Every download is audited with document, version, and size | Accountability |
| Single byte ranges are supported | Large PDFs on a slow network; unsatisfiable and multi-range requests return `416` |

### 5.3 The permission payload

```json
{
  "entries": [
    { "subject_type": "user",  "subject_id": "0192...", "capabilities": ["view","read"], "effect": "allow" },
    { "subject_type": "group", "subject_id": "0192...", "capabilities": ["view"],        "effect": "deny"  }
  ]
}
```

`PUT` replaces the whole set. These all return `422`:

- an unknown subject
- an attempt to grant more than you hold
- removing the owner's floor
- a `deny` entry created by a non-admin

### 5.4 Renditions

A rendition is one rendered page of one version. The browser never receives a blob address.

| Method | Path | Capability needed |
|---|---|---|
| `POST` | `/documents/{id}/versions/{n}/renditions` | `read`. Body: the recipe, the page, the kind. Returns a one-time ticket. |
| `GET` | `/renditions/{ticket}` | Ticket only, plus the session |

```json
{ "page": 1, "kind": "preview", "recipe": { "rotate": 90, "grayscale": true } }
```

| Rule | Reason |
|---|---|
| `read` is required, not `view` | A preview shows content (`06` §6) |
| The recipe is sent on every request, not read from the database | The editor previews unsaved changes |
| An unsaved recipe is never cached | Only the saved recipe's renditions persist |
| Response is `image/png` for images, `image/png` for PDF pages, `application/pdf` for the print path | One image format for the browser |
| `Content-Disposition: inline`, `Cache-Control: no-store` | No disk cache survives the session |
| Ticket lives 60 s, works once, bound to user and IP | Same model as downloads |
| Page count and dimensions are returned with the ticket | The viewer builds its thumbnail rail without extra calls |

Renditions are generated lazily. A request for a page that is not cached blocks until it is
rendered, bounded by the worker timeout (`12` §11). The frontend shows progress after 1 s rather
than pretending it is instant (`11` §12).

### 5.5 The render recipe

| Method | Path | Capability needed |
|---|---|---|
| `GET` | `/documents/{id}/versions/{n}/render-settings` | `view` |
| `PUT` | `/documents/{id}/versions/{n}/render-settings` | `write`, plus `If-Match` |
| `DELETE` | `/documents/{id}/versions/{n}/render-settings` | `write`. Resets to "as stored". |

```json
{
  "rotate": 90, "straighten": -1.5, "crop": [0.02, 0.03, 0.98, 0.97],
  "brightness": 12, "contrast": 8, "gamma": 1.0,
  "grayscale": true, "invert": false, "threshold": null,
  "despeckle": false, "auto_trim": false
}
```

Validation, all `422`: unknown key, out-of-range value, crop outside `[0,1]`, crop with zero area,
`straighten` beyond ±15, `threshold` set while `grayscale` is false.

Saving a recipe **does not create a version** and does not change `blob_addr`. It writes
`version_render_settings`, invalidates that version's renditions, and audits
`document.render_settings_changed` with the old and new recipe hashes (`10` ADR-036).

### 5.6 Print jobs

| Method | Path | Capability needed |
|---|---|---|
| `POST` | `/print-jobs` | `print` on **every** item. Returns the PDF stream. |
| `GET` | `/print-jobs` | `view` of the documents in each job; admins see all |
| `GET` | `/print-jobs/{id}` | Same |

```json
{
  "layout": { "cells_per_side": 4, "duplex": true, "flip_edge": "long",
              "paper": "A4", "orientation": "portrait",
              "margin_mm": 5, "gutter_mm": 4, "fit_mode": "contain" },
  "items": [
    { "version_id": "0192...", "pages": "1-2" },
    { "version_id": "0192...", "pages": "all" }
  ]
}
```

| Rule | Reason |
|---|---|
| The response **is** the PDF: `Content-Type: application/pdf`, `Content-Disposition: inline` | One round trip |
| `Cache-Control: no-store` | The job must not survive in a cache |
| No `Location` for a stored file, because none is stored | There is no artifact to fetch twice |
| The job row is written **before** generation; `X-Print-Job-ID` identifies it | A crash leaves it interrupted until startup recovery marks it failed and records the terminal audit event |
| `GET /print-jobs` and `GET /print-jobs/{id}` return metadata only | Caller must be able to view every source document; admins see all |
| `404` if any item is not visible; `403` naming `print` if visible but not printable; `403 PRINT_RESTRICTED` if the item is `restricted` and the grant is not explicit | `06` §6, `13` §6 |
| `422` for a bad range, bad layout, or over 100 items / 500 pages; `413` over 32 MiB of unique sources | Errors name the item index |
| `504` if generation exceeds 120 s | The connection is closed, not left hanging |
| `Idempotency-Key` is ignored; a reprint is a new job | Two prints are two facts |

The frontend opens the response in a new tab and calls the browser's print dialog (`11` §10).
Saved recipes are applied in the isolated worker. The output is validated before it is returned;
there is no client-side PDF assembly.

## 6. Taxonomy, search, audit, and vault

| Method | Path | Notes |
|---|---|---|
| `GET` `POST` | `/doc-types` | `GET` returns the whole two-level tree: categories, each with `types[]`, and every row carrying `code`, `name`, `parent_id`, `default_confidentiality`, `requires_expiry`, `retention_months`, `side`, `purpose`, `is_system`, `sort_order`, and `row_version`. `POST` is admin-only; `code` cannot change after creation. |
| `PATCH` `DELETE` | `/doc-types/{id}` | Admin; both require `If-Match`, and updates return a new ETag. Rename, re-parent within the two-level limit, or change defaults. Delete is refused if documents use the type (`409`, with the document count), if a category still has types, or for seeded rows (`is_system`; `13` §9). |
| `GET` `POST` | `/tags` | |
| `DELETE` | `/tags/{id}` | Detaches from documents; does not delete documents |
| `GET` | `/search` | Metadata search across entities and documents, permission-filtered |
| `GET` | `/audit` | `auditor` or `admin`. Filter by `actor_id`, `action`, `object_id`, `from`, `to`. |
| `POST` | `/audit/verify` | Admin. Re-walks the chain and returns the first broken `seq`. |
| `GET` | `/vault/status` | Admin: fingerprint, size, blob count, last dump and whether it is encrypted, PostgreSQL version, lock state |
| `POST` | `/vault/dump` | Admin: write an encrypted dump now |
| `POST` | `/vault/verify` | Admin: `202` plus a job ID, for a full hash pass |
| `GET` | `/vault/jobs/{id}` | Job status and summary |
| `GET` `PUT` | `/settings` | Admin. Allow-listed keys only. |
| `GET` | `/healthz` | Liveness. No authentication, no details. |
| `GET` | `/readyz` | Database, vault, and unlock state. `503` when not ready. |

`GET /audit` returns `{items, total}`, newest first. Each item carries `seq`, `ts`, `actor_id`,
`action`, `object_type`, `object_id`, `outcome`, `source_ip`, `detail`, and `file_month`; `limit`
is 1–200 (default 50) and `offset` pages the result. `POST /audit/verify` requires the CSRF header
and returns `{ok, entries, first_bad_seq, detail}`, walking the files rather than the database index.

`GET /vault/status` returns the manifest identity, absolute `root`, `size_bytes`, `blob_count`,
`audit_entries`, the parsed `last_dump`, `last_dump_encrypted`, `postgres_version`, and
`lock_state` (`free`, `held`, or `stale`). It never returns key material.

The `/doc-types` tree is what the upload dialog and the filter rail both read, so it is one call,
not two:

```json
[
  {
    "id": "0192...", "code": "property", "name": "Property and assets", "parent_id": null,
    "types": [
      { "id": "0192...", "code": "sale_deed", "name": "Sale deed",
        "default_confidentiality": "restricted", "requires_expiry": false,
        "retention_months": null, "is_system": true }
    ]
  }
]
```

Ordering is `doc_types.sort_order`, then `code`, so the list is stable across restarts and
matches the printed packet order (`12` §10).

## 7. Security headers on every response

```http
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'; script-src 'self'; worker-src 'self' blob:; img-src 'self' blob: data:; style-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cache-Control: no-store
```

Three directives changed when the viewer arrived, and each one has a reason:

| Directive | Value | Why |
|---|---|---|
| `worker-src` | `'self' blob:` | PDF.js runs its parser in a worker built from a Blob URL |
| `img-src` | `'self' blob: data:` | Rendered pages arrive as image responses and are also drawn to canvas |
| `script-src` | `'self'` | **No `'unsafe-eval'`.** PDF.js only needs it for embedded PDF JavaScript, and we reject PDFs that contain any |

`object-src 'none'` stays. Pages are drawn to a canvas, never handed to a plugin. `frame-ancestors
'none'` stays, so a rendered page cannot be framed by another site on the network.

No CORS headers are sent. The app is same-origin. A request from another origin is either a bug
or an attack, and neither deserves a pre-flight response.

## 8. Rate limits

| Endpoint class | Limit |
|---|---|
| `POST /auth/login` | 5 per 5 minutes per username; 20 per 5 minutes per IP |
| `POST /auth/totp/verify` | 5 per 5 minutes per session |
| Mutations (`POST`, `PATCH`, `DELETE`) | 60 per minute per user |
| Downloads | 120 per minute per user |
| Renditions | 600 per minute per user |
| Print jobs | 10 per minute per user |
| Reads | 600 per minute per user |
| `POST /vault/verify` | 1 concurrent, 1 per hour |

Limits are held in memory in the process. With one worker, that count is exact.

## 9. Versioning and compatibility

- Breaking changes need `/api/v2`.
- Within `v1`, allowed: new optional request fields, new response fields, new endpoints, and new
  values for output-only enums. Clients must ignore unknown response fields.
- Removing a field or tightening validation is breaking.
- Deprecations are announced in the OpenAPI description and logged at `WARN` when used.
- The frontend and backend ship together. The API contract exists for scripts and for the curl
  examples in `08`.

## 10. Contract tests that must exist before the UI

1. Every route returns `401` without a session, except login and health.
2. Every state-changing route returns `403` without `X-CSRF-Token`.
3. Every read route returns `404` for a document the caller cannot `view`.
4. Every PATCH and DELETE returns `428` without `If-Match`, and `409` with a stale one.
5. Uploading a renamed `.exe` returns `415`.
6. Uploading one byte over the cap returns `413` and leaves no file in `vault/tmp/`.
7. The same `Idempotency-Key` twice returns one document.
8. A download ticket works once, then returns `410`.
9. `GET /documents` counts match the caller's visible set exactly.
10. A rendition request without `read` returns `403`; for an invisible document, `404`.
11. A print job containing one invisible document returns `404` and generates no bytes.
12. A print job over the page limit returns `422` naming the item index.
13. A print job leaves no new file under the vault except the audit file.
14. Saving a recipe does not change `blob_addr` or `version_count`.
15. Every error path returns `problem+json` with a `request_id`.
