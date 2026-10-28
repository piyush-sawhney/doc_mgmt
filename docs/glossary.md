# Glossary

> **In plain words:** This page explains every technical word used in these documents. If a
> word in another document is unfamiliar, look it up here. You do not need to read this page
> start to finish.

---

## 1. The six words to learn first

| Word | Plain meaning |
|---|---|
| **Vault** | The one folder on disk that holds everything: encrypted documents, the database backup, the audit log, and the key file. Copy the folder and you have a backup. |
| **Entity** | The person or organisation the paperwork is about. A person is an entity. A company is an entity. |
| **Document** | One piece of paperwork, such as a PAN card or a signed contract. A document is a container; the actual files inside it are versions. |
| **Version** | One uploaded file. Once uploaded, a version never changes. Correcting a mistake means adding a new version, not editing the old one. |
| **Capability** | One specific thing a user is allowed to do, such as "read the file" or "delete the document". Permissions are built from capabilities. |
| **Category** | The shelf a document belongs on: identity, property, legal, corporate, financial, employment, insurance, other. It comes from the document's type. |

If you understand those six, you can follow most of the documentation.

## 2. Full glossary

Entries are alphabetical. "Where" points to the document that explains the idea in detail.

| Term | Plain meaning | Where |
|---|---|---|
| **AAD** (Additional Authenticated Data) | A label attached to an encrypted value that must match when decrypting. It stops a ciphertext from being moved from one column to another and still working. | `05` §5 |
| **ACL** (Access Control List) | A list attached to a document or an entity saying who may do what. | `06` |
| **Address** (blob address) | The 64-character name of an encrypted file, calculated from its contents. It is not the user's filename. | `03` §4 |
| **Admin** | The role that can create users, change the vault, and purge documents. Admins can read all metadata. Reading document content still requires a written reason (break-glass). | `06` §3 |
| **Argon2id** | A deliberately slow password-hashing function. It turns the vault passphrase into a key and makes guessing expensive. | `05` §1 |
| **Audit log** | An append-only record of who did what and when. Entries are chained together so edits are detectable. | `03` §10 |
| **Auditor** | A role that can see that a document exists and read the audit log, but cannot download content unless separately granted. | `06` §3 |
| **Blind index** | A keyed fingerprint of a value, stored so the app can find an exact match without storing the value in readable form. | `05` §6 |
| **Blob** | The encrypted bytes of one document version, as stored on disk. | `03` §5 |
| **Break-glass** | An admin's audited, reason-required access to document content they were not granted. | `06` §9, `09` §11 |
| **Ciphertext** | Data that has been encrypted and cannot be read without the key. | `05` |
| **CSRF** (Cross-Site Request Forgery) | An attack that tricks a logged-in browser into sending a request the user did not intend. A per-session token blocks it. | `07` §2 |
| **Category** | One of eight fixed shelves a document belongs on, such as property or legal. Derived from the document's type, never stored separately. | `13` §3 |
| **Custodian** | A person who holds a copy of the vault passphrase. | `08` §7 |
| **Document type** | The specific kind of paper inside a category, such as a PAN card or a sale deed. Every document has exactly one. It carries a default sensitivity. | `13` §3 |
| **DPAPI** | The Windows data-protection interface. It encrypts a value so that only a specific machine or user account can read it back. Used here for the database password. | `08` §2.2 |
| **Dump** | A portable copy of the whole database, produced by `pg_dump`. It lives inside the vault and is encrypted. | `03` §9 |
| **`DVC1`** | The name of the blob file format: a 96-byte header followed by encrypted content. | `03` §5 |
| **`DVD1`** | The name of the dump file format: a 32-byte header followed by encrypted 64 KiB chunks. | `03` §9.1 |
| **`DVK1`** | The name of the key-file format: exactly 96 bytes holding the wrapped vault master key. | `03` §6 |
| **Editor** | A role that can create and change documents, but cannot manage users or purge. | `06` §3 |
| **Duplex** | Printing on both sides of one sheet. The PDF carries front, back, front, back in order; the printer dialog must be told to flip. | `12` §5 |
| **Entity** | A person or organisation that documents belong to. | `00` §4 |
| **Envelope encryption** | Encrypting data with a key, then encrypting that key with another key. Changing the outer key does not require re-encrypting the data. | `05` §2 |
| **File key (FK)** | A random key created for one version, used to encrypt that version's bytes. It is stored wrapped inside the blob. | `05` §2 |
| **GCM** (Galois/Counter Mode) | The encryption mode used here. It encrypts and also detects tampering. | `05` §1 |
| **HKDF** | A method for deriving several different keys from one master key, so each purpose gets its own key. | `05` §3 |
| **HMAC** | A keyed hash. It proves a value came from someone who holds the key, and it is used to name blobs and build blind indexes. | `05` §6 |
| **Identifier** | A typed ID value attached to an entity, such as a PAN, GSTIN, CIN, DIN, or passport number. Stored as its own row, not as a column. | `04` §4 |
| **Immutable** | Cannot be changed after creation. Versions are immutable. | `04` §5 |
| **KEK** (Key-Encryption Key) | The key that encrypts other keys. Here, `file_kek` wraps each version's file key. | `05` §2 |
| **Key fingerprint** | A short public value derived from the vault master key. It identifies the key without revealing it. | `03` §3 |
| **`dump_key`** | The sub-key derived from the vault key that encrypts database dumps. | `05` §5.1 |
| **Legal hold** | A flag that blocks purging a document, usually because of a dispute or investigation. | `04` §8 |
| **Manifest** | `manifest.json` at the vault root. It records the vault's identity, format version, and key fingerprint, and it is signed. | `03` §3 |
| **Nonce** | A random number used once per encryption. Reusing one would break GCM, so each encryption gets a fresh one. | `05` §1 |
| **N-up** | Placing several document pages on one printed side, in a grid. 4-up means four cells. | `12` §3 |
| **Orphan blob** | An encrypted file on disk that no database row points to, usually left by a failed upload. | `08` §5.1 |
| **Operator-managed PostgreSQL** | The database server is installed, started, and patched by the person running the system. The app connects to it and never manages it. | `02` §6.3 |
| **Passphrase key (PK)** | The key produced by running the passphrase through Argon2id. It exists only in memory and is never stored. | `05` §2 |
| **Plaintext** | Data before encryption, or after decryption. | `05` |
| **Print capability** | The right to include a document in a print job. Separate from `read`. Denying `read` also removes it. | `06` §2 |
| **Print job** | One print request: an ordered list of versions, a layout, and a record of who printed it. No file is kept. | `12` §2 |
| **`PRINT_RESTRICTED`** | The error returned when a `restricted` document is printed without an explicit grant on that document. It means the classification is working. | `13` §6 |
| **Purge** | Permanently removing a document's content. Admin-only, requires a prior soft delete, and is audited. | `09` §16 |
| **Reader** | A role that can view metadata and download documents it has been granted. | `06` §3 |
| **RPO** (Recovery Point Objective) | How much data you can afford to lose, measured in time. Here: up to 24 hours. | `08` §12 |
| **RTO** (Recovery Time Objective) | How long you can afford to be down. Here: about one hour for a 100 GB vault. | `08` §12 |
| **Recipe** (render recipe) | The saved adjustments for a version: rotation, crop, brightness, and so on. It changes rendering and printing, never the stored file. | `11` §8 |
| **Rendition** | One page of a version rendered for the screen or for print. Cached as an encrypted blob, and safe to delete. | `03` §5.1 |
| **Render worker** | The separate process that decodes images and PDFs and builds pages. It never holds a vault key. | `02` §6.4 |
| **Salt** | Random bytes added before hashing so identical inputs produce different outputs. | `03` §4 |
| **Sensitivity** | How carefully a document must be handled: `normal`, `sensitive`, or `restricted`. It changes permissions and warnings, never how the file is stored. | `13` §6 |
| **Soft delete** | Marking a document deleted while keeping its files. Reversible. | `09` §16 |
| **TOTP** | A six-digit code from an authenticator app, used as an optional second login step. | `07` §2 |
| **Vault root** | The absolute path to the vault folder. It is the only absolute path stored anywhere. | `03` §13 |
| **Version** | One uploaded file belonging to a document. | `04` §5 |
| **VMK** (Vault Master Key) | The 32-byte root key of the vault. Everything else is derived from it. It is stored only in wrapped form. | `05` §2 |

## 3. Acronyms at a glance

| Short form | Stands for | In plain words |
|---|---|---|
| **ACL** | Access Control List | Who may do what to a document |
| **AAD** | Additional Authenticated Data | A label that binds a ciphertext to its column |
| **CSRF** | Cross-Site Request Forgery | A tricked-browser attack, blocked by a token |
| **CIN** | Corporate Identity Number | Indian company registration number |
| **DIN** | Director Identification Number | Indian director registration number |
| **DPDP** | Digital Personal Data Protection Act, 2023 | India's data-protection law |
| **DPAPI** | Data Protection API | Windows encryption tied to a machine or account |
| **DVD1** | DocVault Dump, version 1 | The encrypted container format for database dumps |
| **GCM** | Galois/Counter Mode | Encrypts and detects tampering |
| **GSTIN** | Goods and Services Tax Identification Number | Indian tax registration number |
| **HKDF** | HMAC-based Key Derivation Function | Derives separate keys from one master key |
| **HMAC** | Hash-based Message Authentication Code | A keyed hash used for naming and indexing |
| **KEK** | Key-Encryption Key | A key that encrypts other keys |
| **PAN** | Permanent Account Number | Indian tax ID for a person or entity |
| **RPO / RTO** | Recovery Point / Time Objective | How much data you can lose / how long you can be down |
| **TOTP** | Time-based One-Time Password | The six-digit code from an authenticator app |
| **VMK** | Vault Master Key | The root key of one vault |

## 4. Words this system avoids on purpose

| Word you may expect | Why we do not use it |
|---|---|
| "Zero-knowledge" | The server can decrypt documents while running. That is not zero-knowledge, and claiming it would be false. |
| "Military-grade encryption" | A marketing phrase with no technical meaning. We state the algorithm and key size instead. |
| "Crypto-shredding" | It is not possible here, because each blob carries its own key. `10` ADR-011 explains why. |
| "Deleted" | Ambiguous. We say **soft delete** (reversible) or **purge** (permanent). |
| "Secure" | Too vague to test. We name the control: encryption, ACL, audit, or TLS. |
