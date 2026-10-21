# intake

Single-use, browser-encrypted secret intake into a dedicated Bitwarden or
Vaultwarden collection. An operator creates a ticket on the host, shares its
one-time link, and receives a metadata-only completion or failure email after the
writer processes the submission. Tickets cannot be created through HTTP.

The service has two non-root processes and two SQLite databases. The public web
process can store encrypted submissions but cannot read ticket private keys or
the writer master key. The writer necessarily sees plaintext while handing it to
the vault. This is not a zero-knowledge service.

## Architecture

```text
Operator (CLI, intake-writer account)
  | creates ticket + per-ticket RSA keypair; prints link once
  +----> public SQLite: HMAC, metadata, public JWK, ciphertext queue
  +----> private SQLite: encrypted PKCS8 private key + trusted AAD metadata
  |
  +---- private delivery of https://intake.example.com/#req=<id>.<secret>
                                        |
Recipient browser                       |
  | GET static page; capture fragment once and immediately clear it
  | wait for explicit Open form before app-initiated network requests
  | POST /api/open: token -> display metadata + trim + metaDigest + public JWK
  | apply ticket whitespace policy; reject empty; encrypt value locally
  | POST /api/submit: token + encrypted envelope -> 202 queued receipt
  v
HTTPS reverse proxy -> loopback HTTP web (intake-web)
                         | atomic single-use claim + durable pending enqueue
                         | shared SQLite (web-writable queue and state)
                         +---- Unix socket wake-up, ticket id only ----+
                                                                     |
Writer (intake-writer) <---- periodic poll of public SQLite -----------+
  | pending -> processing before vault sync/write
  | read encrypted private key + writer master key; decrypt in memory
  +---- writer-only Unix socket ----> unlocked bw serve ----> dedicated collection
  | ambiguous write / interrupted processing -> unknown; retain envelope + key
  | later, after max(settle, backoff): sync + marker lookup; create only if absent
  | commit done + notify_pending; discard ciphertext; delete private key
  +---- HTTPS ----> mail API ----> ticket creator, metadata only
```

The diagram shows the non-Docker loopback proxy variant. Docker uses a dedicated
tunnel network and a container-local `0.0.0.0` listener instead, with the same
SQLite and Unix-socket trust boundaries described below.

The web and writer communicate through **both the shared, web-writable ticket
SQLite database and the Unix wake-up socket**. The database is the durable queue;
the socket carries ticket-ID wake-ups, notification retries and revocations, not
all communication between the processes. Web must be able to write the SQLite file and its
WAL/SHM sidecars. “Public” describes its trust boundary, not an Internet-downloadable
file. The writer treats its metadata as untrusted: the original target, key name,
purpose, trim policy and notification address come from writer-only SQLite and
are bound to each encrypted submission by canonical AAD.

A compromised web process with database write access can delay, drop or reorder
submissions; change/delete rows, timestamps, ciphertext, lifecycle and notification
states; falsify completion/failure or the database fingerprint; and suppress or
retrigger notifications to the original recipient. It can bypass normal HTTP
authorization, shared expiry and single-use checks and can encrypt an
attacker-chosen value using the public key and metadata, but cannot undo
writer-private revocation or bypass the private first-seen expiry check described
below. Queue integrity, lifecycle integrity and exactly-once processing are
therefore **not guarantees against a malicious web account**. It cannot use shared metadata edits to redirect a writer vault write
or mail to a different target/recipient: the writer compares against its private
snapshot, uses that snapshot for AAD, vault target and notification metadata, and
fails closed on a mismatch. Web cannot read the writer keys/private database or
decrypt previously queued ciphertext under the documented permissions. It can,
however, replace served JavaScript or public keys to steal future inputs. These
boundaries do not make a compromised web origin safe.

## Security boundaries

The shared ticket database / `intake-shared` volume contains only public display
metadata (ID, key name, purpose, trim policy), a metadata digest, token HMACs,
public RSA JWKs, encrypted submission envelopes, timestamps, lifecycle and
notification state, and completion fingerprints. It contains **no private keys
(even encrypted), writer master/fingerprint keys, private metadata snapshots,
target item/field/notes, notification addresses, or plaintext submitted values**.
The token HMAC key is mounted separately into web and writer; it is not stored
in either database. The digest is not encryption: guessable target/recipient
metadata can still be tested against it offline.

Everything read from the shared database is untrusted. Web checks token HMAC,
expiry, active state, canonical digest format and envelope shape when opening or
claiming a ticket. Writer atomically claims queue state, fetches trusted metadata
and the encrypted key by ticket ID from private SQLite, recomputes the private
metadata digest, compares the shared digest and public AAD fields, and decrypts
and validates the authenticated envelope before choosing a target. Writer-private
metadata also latches revocation and the writer's first sight of submitted work;
shared timestamps cannot extend its private expiry. Shared state alone is not an
authorization boundary against a compromised web account. Notification recipients
and content always use the private snapshot, including on retries.

| Process / storage     | Visibility                                                                                                                                                                                    |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Browser               | Link token, public display metadata/digest/JWK and their own plaintext input; not target/recipient or writer keys                                                                             |
| web / `intake-shared` | Shared queue contents above; web also has the separate token HMAC secret and wake-up socket access                                                                                            |
| writer / CLI          | Shared DB plus writer-only `intake-writer` DB: encrypted per-ticket keys and plaintext trusted metadata; separate master/fingerprint/mail secrets; plaintext only in memory during processing |
| bw / `bw-data`        | Dedicated vault profile/cache and API credentials, unlock session in process memory, and accessible collection contents; no ticket DB mounts                                                  |
| `intake-sock`         | Ticket-ID wake-up, notification-retry and revocation socket; writer writes, web mounts read-only                                                                                              |
| `bw-sock`             | Unauthenticated vault API socket; bw and writer only, never web                                                                                                                               |

**Shared metadata migration:** opening an older database removes its
`target_json` and `notify_email` columns; no private snapshot or digest is ever
backfilled from shared data. Existing digest-bound tickets continue using their
private snapshot. Digest-less tickets or missing private metadata fail closed;
drain/revoke and reissue old-format tickets with a coordinated CLI/web/writer
upgrade. `list`/`show` need only shared summary columns, not target/recipient data.
Stop all DB users before upgrading and, after migration, perform an offline
SQLite WAL checkpoint/truncate and `VACUUM` if removal of historical plaintext
from the current files is required. Dropping columns cannot retract old WAL
frames, backups, filesystem snapshots, or storage history; restrict and expire
those copies separately. Newly created databases never store that plaintext.

### Data and ordering guarantees

The following describe normal application operation, not an attacker modifying
the shared database directly.

1. `create` generates a random 16-byte ticket ID and a 32-byte (256-bit) token
   secret, both encoded as base64url. Only HMAC-SHA256 of `id + '.' + secret`
   under the server HMAC key is stored; comparisons are timing-safe. The complete link is printed once and
   cannot be recovered from storage.
2. Each ticket has its own 3072-bit RSA-OAEP/SHA-256 keypair. Its public RSA JWK is
   in the public database. The PKCS8 private key is encrypted with AES-256-GCM
   under the separate 32-byte writer master key and stored in the writer-only
   database. Neither the master key nor that private database is available to
   the web account.
3. Loading the page does not consume the ticket. On load, the browser captures
   `location.hash` **once** into memory and immediately removes the fragment with
   `history.replaceState`, before any app-initiated network requests. The initial
   document and static asset loads do not send the fragment; no token is sent in
   an HTTP request URL, path, or query string. Clicking **Open form** sends the
   token in a JSON POST body and records `opened_at`, without consuming it. The
   response includes only the ID, key name, purpose, boolean `trim` policy,
   expiry, public JWK and `metaDigest` for AAD. Target item/field/notes and the
   notification address are **not sent to the browser**. Refreshing after fragment
   removal loses the token from that page; reopen the original link if it has not
   been submitted.
4. Before encryption, browser `encryptValue` applies `String.prototype.trim()`
   semantics when `trim=true` (the default), removing leading/trailing whitespace
   and line breaks. With `trim=false` (`--keep-whitespace`), the exact supplied
   value is preserved, including nonempty whitespace-only values. A zero-length
   value after applying the policy is rejected before encryption. The accepted
   value must be 1–65,536 UTF-8 bytes. The browser encrypts it with a fresh
   AES-256-GCM key, random 96-bit IV, and 128-bit authentication tag, then wraps
   the AES key with the ticket public key. Canonical authenticated data (AAD) is
   the UTF-8 encoding of
   `JSON.stringify([id, keyName, purpose, trim, metaDigest])`: a fixed-order
   five-element JSON array with `trim` as a **boolean**, not a string or number.
   At creation the CLI computes `metaDigest` as the lowercase 64-character hex
   SHA-256 of the UTF-8 encoding of
   `JSON.stringify([{item, field, notes}, notifyEmail])`. Target object keys are
   always exactly `item`, `field`, `notes` in that order; omitted notes become
   `""` during input validation. Strings are preserved without whitespace, case
   or Unicode normalization. This digest is stored in **both** databases.
   Browser and server import the same AAD encoder. The writer recomputes the
   digest from its **own private snapshot**, checks both stored digests and the
   shared metadata against it, and builds decryption AAD from that recomputation.
   Changing any bound metadata, including target notes or notification address,
   fails authentication or the metadata comparison before any vault write.
5. `POST /api/submit` verifies authorization, expiry, and unused status, validates
   the envelope, and atomically changes `active` to `pending` while storing the
   ciphertext in one immediate SQLite transaction. Concurrent valid submissions
   have one winner. Wrong/invalid, expired, revoked, and used tokens receive the
   same generic terminal API error, `ticket_unavailable`, without revealing which
   condition applies. Loading or opening a ticket never reserves its use for one
   browser.
6. HTTP `202` means **durably queued**, not successfully stored in the vault.
   Web returns only the pending status, never a fingerprint. A socket wake-up is
   an optimization; the writer also
   polls SQLite, so a missed wake-up does not lose accepted work. The socket
   carries only the ticket ID, not the value or ciphertext.
7. The writer atomically claims due `pending` work as `processing`, reads its
   private metadata, rejects private revocation, and latches its first-seen time.
   First sight later than private expiry plus the grace period (15 minutes by
   default) fails as `ticket_expired`. Only then does the production writer check
   the local vault's non-mutating `/status`, before decrypting or making any vault
   sync/write request. An unavailable/locked API returns the claimed ticket to
   `pending` with `failure_code=vault_unavailable`, increments persisted `attempts`,
   and schedules exponential backoff, retaining ciphertext and the private key.
   Timely first sight preserves later retries even after expiry; terminal
   notification work remains independent. Sync failures and item-connect failures
   proven to send nothing also return to `pending` with persisted backoff. An
   ambiguous item request becomes nonterminal `unknown`, retaining the envelope
   and key without sending mail. A later writer run waits for persisted
   settle/backoff, then synchronizes and looks up the exact ticket marker plus the
   expected fingerprint
   before deciding whether a create is needed (see crash recovery below). It
   validates plaintext without silently changing it: when `trim=true`,
   a value that is not already trimmed or is empty after applying the policy is
   rejected as `invalid_payload`. When `trim=false`, only zero-length values are
   empty; nonempty whitespace-only values are valid and preserved exactly. The
   writer also enforces the UTF-8 byte limit. Rejecting rather than defensively
   trimming keeps the stored value and fingerprint consistent with the browser's
   policy-applied value. Rejection consumes the ticket: it becomes `failed`, not
   reusable, and no vault write occurs. Successful writes or a uniquely matched
   recovery lookup become `done`; definitive non-retryable failures become
   `failed`. Ciphertext is removed on either terminal transition, and normal
   processing also deletes the encrypted per-ticket private key. Nonterminal
   `pending`, `processing`, and `unknown` tickets retain both. Only the writer computes a completion fingerprint: the first 16 hex
   characters (64 bits) of **HMAC-SHA256(fingerprintKey, canonical(ticketId, value))**,
   using an independent writer-only 32-byte key. The canonical input is exactly
   the UTF-8 encoding of `JSON.stringify([ticketId, acceptedValue])`, a fixed-order
   JSON array of two strings; whitespace in the accepted value is preserved.
   Including the ticket ID prevents cross-ticket value-equality matching. This
   keeps the existing compact comparison length; it is not a collision-proof
   identifier or attestation. The writer stores it with the ticket and adds
   `intake_ticket_id` and `intake_fingerprint` custom fields to the vault item
   before committing completion; `intake list` shows the stored fingerprint.
8. `done` and `notify_status=pending` are committed together **before** attempting
   completion mail, including completion through marker lookup. Mail failure never
   rolls back a vault write. Terminal failed writer work also gets a best-effort
   metadata-only failure notification. `unknown` sends neither completion nor
   failure mail until resolution reaches a terminal state.

SQLite uses WAL journaling, `synchronous=FULL`, a five-second busy timeout, and
secure deletion for removed records. Durable enqueueing still depends on the
host filesystem and storage honoring synchronization; backup, filesystem, and
storage failure are not solved by the application.

Ticket creation and private-key pruning both acquire the public database's
immediate write lock before accessing private storage. This prevents startup or
purge from deleting a newly inserted private key before its public ticket is
committed. A crash before public publication can leave an encrypted orphan key,
which the next locked cleanup removes. The two files do not need a distributed
transaction to preserve this publication invariant.

Creation atomically stores a writer-only snapshot of ID, key name, purpose,
`trim`, target, notification address and their metadata digest alongside the
encrypted private key in private SQLite. The writer builds decryption AAD (with a
recomputed digest), the vault target and notification metadata/recipient **only
from that snapshot**, never from a socket payload or shared metadata. It also
compares shared metadata and its stored digest to its snapshot before processing;
a mismatch consumes the submission as failed without a vault write, and any failure
mail goes only to the original address. Target/recipient plaintext is absent from
the shared schema; lifecycle-only reads keep notification recovery independent of
untrusted display metadata. Private metadata survives
per-ticket key deletion for notification retries and is removed when the public
ticket is purged (or orphaned); it contains no secret value.

### Browser flow and value entry

The value field has an in-field eye icon
and a manual `toggleSecret()` show/hide control. The editor is a visually masked
textarea rather than a native password input, because password/text inputs strip
line breaks before encryption. Raw pasted line endings are retained in memory
separately from the textarea's normalized display, including when the value is
edited. WebCrypto and CSS `-webkit-text-security` support are required; unsupported
browsers never expose an unmasked entry field. There are no
whitespace hints, warnings or banners and no automatic hiding of a revealed value.
The field hint is always "Paste the value as issued."; trimming (the `trim`
metadata returned by `/api/open`) is applied silently before encryption.

The real flow is landing → explicit **Open form** → form → explicit **Send
securely** → queued confirmation. The state is driven only by this flow, never by
query parameters. Opening the form does not reserve the ticket.

Invalid links and terminal `ticket_unavailable` errors leave only the error
page: the form and secret input are removed completely, with no retry button.
This also applies when a submit loses a race to another browser or the ticket
expires or is revoked while the form is open. Transient network errors, HTTP 429,
and HTTP 5xx may retain the form for a deliberate user retry, but submissions
are **never automatically retried**. A network error can hide an already accepted
submission; a later attempt may therefore return `ticket_unavailable`.

After HTTP `202`, the confirmation says the encrypted submission was received
and queued, **not that the secret is already stored in the vault**. Neither web
nor browser computes or receives a fingerprint or its key. The writer's
completion notification reports the fingerprint after a successful vault write.

### Crash recovery and ambiguous vault writes

**Provably pre-delivery initial failures return to `pending`.** A failed/locked
`/status` preflight returns already-claimed work to pending with
`failure_code=vault_unavailable`, an incremented retry counter and persisted
backoff. A failed initial `/sync` also requeues claimed work: no item request has
started. Item request `ECONNREFUSED`, `ENOENT`, `EACCES`, or `ECONNRESET` is
retryable only when a fresh socket was
observed connecting and never emitted `connect`. Connections are not reused.
Neither `bytesWritten` (which includes buffered writes) nor an unfinished request
proves zero delivery. `VaultError`'s ambiguous flag is reserved for failures of
an actual item POST: **every such error is ambiguous unless pre-delivery is
proven**. Examples include timeout after send, reset after connection/flush,
malformed or invalid 2xx response (including a missing item ID), oversized
response, and any non-2xx response, including **HTTP 4xx/400** or 5xx. The pinned
CLI's [`createWithServer` error handler](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/apps/cli/src/vault/create.command.ts)
converts caught failures to `Response.error`, and
[`bw serve` maps failed command responses to HTTP 400](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/apps/cli/src/oss-serve-configurator.ts#L451-L461).
An HTTP 4xx response therefore does **not** prove that no item was written and
must not terminal-fail an actual item POST. These errors become `unknown`, retain
envelope/key, and are not immediately re-POSTed. Adapter validation that fails
**before** the item POST remains terminal. All errors remain sanitized; upstream
bodies are never logged.

**`unknown` retains recovery material and sends no notification.** The envelope,
encrypted per-ticket private key, and trusted metadata remain available so the
writer can decrypt again and compute the expected ticket-bound fingerprint.
`list` and `show` expose `unknown`; to the submitter it is already consumed, like
`processing`, so reopening/resubmitting is not possible. Neither completion nor
failure mail is sent until a terminal transition.

Retry scheduling uses persisted `attempts` and `next_attempt_at` in shared
SQLite, initialized to zero for old rows without changing their lifecycle. The
exponential backoff is `min(max, base * 2^previousAttempts)`, using the counter
before incrementing it and defaulting to **5 seconds, 10 seconds, 20 seconds, ...
up to 5 minutes**. Configure writer-only
`INTAKE_VAULT_RETRY_BASE_MS` / `INTAKE_VAULT_RETRY_MAX_MS` (positive integer
milliseconds, base <= max <= 2,147,483,647). The counter saturates at 31; delay
stays capped indefinitely. Failed readiness checks, pre-delivery retries and
`unknown` retries/recovery increment this counter; claiming work alone does not.
Readiness and other pre-delivery pending retries use this backoff.
`database_busy` means local SQLite contention, not a vault rejection; ticket
material and the key are kept, and normal retry timers apply.
Other local errors (e.g. SQLite) before an `unknown` ticket's recovery lookup keep
it `unknown` with `writer_state_failed` and normal backoff, retaining envelope/key;
deterministic metadata, payload, revocation, expiry, and decryption/parse failures
(corrupt key, envelope, or stored metadata) remain terminal.
For a pending ticket, other local errors before the vault write is attempted (for
example SQLite I/O errors) are retried with `writer_state_failed` and normal
backoff, keeping envelope and key. SQLite errors on either path stop the current
batch so later polls can resume without repeating the same database failure for
every due ticket.
Writer-only `INTAKE_STUCK_ATTEMPTS` defaults to **10** and accepts positive safe
integers **1–31**, so the threshold is reachable before counter saturation. On the
persisted increment to that exact count, the writer emits `ticket_stuck` once per
ticket with only `id`, `status`, `attempts`, and safe failure `code`, through the
existing structured logger. Later retries, saturation at 31, and restarts do not
repeat it. Keep the threshold stable for this once-per-ticket behavior; changing
it does not backfill warnings for tickets already past it. Retries and limits are
unchanged: this warning neither stops work nor sends mail. Logging is not atomic
with SQLite; a crash between commit and emission can lose the warning.

After a newly ambiguous item POST, an accepted-write completion-commit failure,
or interrupted-processing recovery, `unknown` resolution runs on a **later writer
run**, after the persisted delay
`max(INTAKE_UNKNOWN_SETTLE_MS, exponential backoff)`. The settle setting defaults
to **120000 ms (2 minutes)** and accepts positive integer milliseconds up to
**2,147,483,647**, writer-only. This minimum wait gives an in-flight CLI create
time to finish; it is not a guarantee that it has finished. Once that wait has
elapsed, subsequent lookup failures, multiple matches, oversized listings, or a
provably pre-delivery replacement-POST failure keep `unknown` and reschedule
with exponential backoff **only**; they do not renew the settle floor. A new
ambiguous POST starts a new settle wait.

Both selection and atomic claim enforce the due time, so wake-ups, polling, and
restarts cannot bypass it. After a failed preflight, the rest of that drain reuses
its unavailable result rather than probing again. Each due pending ticket is
still claimed and checked against private first-seen expiry; eligible tickets are
requeued with their own incremented attempts and backoff. Terminal notification
work runs independently. `unknown` resolution skips `/status` and uses sync plus lookup.
Actual execution can be later than the scheduled due time by the poll interval
and other queued work. Once first seen within private expiry grace, accepted
`pending`, `processing`, and `unknown` work has no total-age cutoff, survives link
expiry and is not purgeable.
Monitor safe error codes, restore vault access, and retain the original master
and fingerprint keys as well as the ticket databases. Invalid metadata/payloads
and decryption failures remain terminal, not transient vault failures.

**Recovery synchronizes and lists the complete dedicated collection.** Each
unknown-resolution lookup unconditionally performs `POST /sync`, even when
`BW_SYNC_BEFORE_WRITE=false`, then
`GET /list/object/items?collectionId=<configured collection id>` **without a
`search` parameter**. The pinned CLI 2026.10.0's
[`searchCiphersBasic`](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/libs/common/src/vault/services/search.service.ts#L104-L167)
does not search custom fields; a ticket-ID search could miss an existing marker.
The pinned CLI's successful list response is
`{"success":true,"data":{"object":"list","data":[...]}}`, as defined by
[`ListResponse`](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/apps/cli/src/models/response/list.response.ts#L3-L10)
and [`Response.success`](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/apps/cli/src/models/response.ts#L60-L65).
The adapter filters the listing strictly in memory: `organizationId` must match,
`collectionIds` must include the configured collection, at least one ticket marker
must equal the exact ticket ID, and at least one fingerprint field must exist with
**all** its values equal to the expected fingerprint computed from the retained
submission. Only text fields (`type === 0`) count for either reference; hidden,
boolean, and linked fields are ignored entirely, including conflicting values.
It reuses creation's collision-aware names: `intake_ticket_id` /
`intake_fingerprint`, or the corresponding `_reference` name when the secret target
uses that name. A marker-only item never matches and leads to one create if no
other item matches. Other organizations/collections, near-match IDs, and any
conflicting fingerprint do not match. The listing is never logged and is
discarded from memory after filtering.

- **One match:** use its item ID and complete as `done`, storing the fingerprint,
  clearing ciphertext/key, and notifying as usual; no create is needed.
- **Zero matches:** issue exactly one item-creation POST for this resolution
  attempt. Its outcome can again be `unknown`; there is no blind write loop.
- **More than one match:** stay `unknown`, log safe code
  `vault_marker_ambiguous`, and do not create another item. Operator
  reconciliation is required.
- **Lookup failure:** stay `unknown` with persisted backoff, not `pending` or
  `failed`; no item-creation POST is made.
- **Listing exceeds `BW_MAX_RESPONSE_BYTES`:** stay `unknown`, log
  `vault_lookup_too_large`, and do not create an item or treat a partial listing
  as empty. Raise the cap or empty/shrink the dedicated collection by moving
  **only items for `done` tickets** out of it. Never move unresolved ticket items.

SQLite and the external vault API cannot share a transaction. On writer startup,
stranded `processing` tickets become `unknown` with a **fresh settle delay**.
Their envelope/key is retained for recovery once private first sight has been
latched within expiry grace, rather than marking them `failed`. If the writer
dies after the claim commits but before first sight is latched, and restarts
after private expiry plus grace, the unseen key can be pruned and the ticket
ends as `ticket_expired`. The socket rejects work until permissions and startup
recovery are complete. If database contention prevents recording a vault outcome,
the serialized writer loop retries local recovery on later polls; once storage
is available, stranded processing follows the same `unknown` transition with a
fresh settle delay. Recovery is itself retried while storage is unavailable.
With timely first sight, both paths eventually perform the lookup above rather
than blindly replaying a create or deleting the recovery material.

**Residual duplicate risk remains.** A timed-out create can finish after the
settle interval, or the vault server can apply it after the recovery sync. An
empty lookup can then authorize another create before the original becomes
visible. Settle/backoff and marker lookup reduce this risk but do not provide
exactly-once delivery. Duplicates are detectable through the exact ticket markers;
more than one matching item on a resolution lookup keeps the ticket `unknown`
with `vault_marker_ambiguous`. This is not a continuous duplicate scan after
`done`, nor silent data loss: an ambiguous outcome retains recoverable work
instead of being discarded as a failure. Reconcile suspected duplicates before
using or moving an entry. Items moved out before resolution cannot be found by
the collection lookup and can cause another create; humans must move entries
**only after the corresponding ticket is `done`**. Never reactivate a consumed
ticket in SQLite or create a replacement without inspecting the existing markers.

Unclaimed `pending` work survives a restart, but the writer must first see it
within its private expiry grace. Work first seen too late fails as
`ticket_expired`, even if submitted before link expiry; timely first sight lets
later retries continue after expiry. An interrupted mail send can be retried on
restart: notifications are **at least once**, and a crash after API acceptance
but before recording `sent` can cause a duplicate email.

## Threat model

### Protected boundaries

- A copied public database contains metadata, token HMACs, public keys, queued
  ciphertext, fingerprints, and notification state, not reusable plaintext
  tokens or ticket private keys. The random token secret resists offline guessing.
- A stolen private database without the writer master key contains encrypted
  private keys and plaintext ticket metadata snapshots, not secret values.
  Keep its backups separate from master-key backups.
- A web-account filesystem compromise does not directly grant access to the
  writer key, private database, mail credential, or unlocked session file when
  the documented permissions are preserved.
- Database opens reject symlinked database files/immediate parents, hard links,
  unsafe permissions, corrupt files, triggers, views and unexpected tables. The shared
  directory and all its contents are treated as untrusted. SQLite opens with
  `trusted_schema=OFF`, `cell_size_check=ON`, its default defensive mode and an
  integrity check. `better-sqlite3` cannot pass `O_NOFOLLOW` to SQLite, so opens
  compare pre/post-open file identity and SQLite's resolved main path instead.
  These checks narrow but do not eliminate filesystem races: a process able to
  replace shared files can still race checks or modify them after opening. Keep
  the private database in a writer-owned `0700` directory, never the shared one.
- Revocation latched in private metadata cannot be undone by editing the shared
  row. The writer also rejects work first seen more than **15 minutes** after its
  private expiry, regardless of shared expiry/status changes. Timely first sight
  is latched before vault readiness checks so later retries and ambiguous-write
  resolution still work. Tickets created before this upgrade lack private expiry
  and retain their previous behavior; revoke/reissue them for this protection.
  CLI `revoke` latches immediately through the socket when reachable; otherwise
  startup/periodic pruning must observe the shared revoked state first. A hostile
  web account can hide that state before it is observed. The socket is reachable
  by web too, but `/revoke` only accepts tickets already marked revoked in the
  shared database, which web can change anyway.
- CLI `list`/`show` escape backslashes, terminal controls and directional controls
  in every displayed field, preventing stored metadata from issuing terminal
  commands or adding rows.
- TLS, fragment-based links, no third-party scripts, and clearing the fragment
  limit routine token leakage. Strict response headers include a restrictive
  CSP, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, a restrictive permissions policy,
  and default `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
  Body limits and process-local per-IP/per-ticket limits reduce basic abuse.
- Application logs are structured JSON lines with a redaction layer and safe
  error codes, not submitted values, tokens, ciphertext, or upstream response
  bodies. The creation link is the intentional exception on CLI stdout; do not
  capture it in logs. Proxy and operating-system logging need separate care.

### Not protected, and operational mitigations

- **Compromised host, root, or writer account:** the attacker can access keys,
  plaintext in memory, unlocked vault capabilities, or delivered application
  code. The web cannot decrypt historical ciphertext by itself, but a malicious
  web process can alter JavaScript/public keys to steal future inputs, modify
  shared metadata, or disrupt work. Browser encryption does not make a hostile
  origin safe. Secure and patch the host and minimize account access.
- **Unlocked `bw serve` API:** its management API is unauthenticated. Earlier
  loopback TCP deployments exposed the unlocked account's capabilities to any
  local user, including a compromised web process; loopback prevents remote
  exposure, not local-user access. The default is now a Unix socket under
  `/run/intake-bw`, owned by the writer UID with mode `0700`. Filesystem traversal
  permissions prevent web and other local accounts from reaching it, even if the
  socket itself has broader permissions. The writer refuses startup if the
  socket parent is not a directory owned by its UID with no group/other access.
  Anything running as the writer user or root can still use the unlocked vault.
  Explicit TCP mode retains the local-user exposure and emits warning code
  `vault_tcp_local_users`; it requires separately verified isolation (see below).
- **Vault account visibility:** Bitwarden cannot cryptographically enforce
  creating entries without reading existing ones in the same accessible
  collection. Use a dedicated service account and a dedicated **Intake**
  collection accessible only to that account, with only the necessary
  organization permissions. It can read everything in collections granted to
  it. Keep the collection small for full-list marker recovery; a human
  administrator moves entries out **only for tickets already `done`**. Moving an
  unresolved entry hides it from recovery and can cause another create. Do not
  place unrelated secrets there.
- **Ambiguous writes and crash recovery:** `unknown` retains ciphertext/key and
  waits for settle/backoff before sync plus exact-marker-and-fingerprint lookup;
  it is not a terminal failure or permission for a submitter to resubmit. This avoids silent
  loss of unresolved work, but cannot guarantee exactly one vault item: a
  timed-out create may finish after settle, or the vault server may apply it
  after sync, allowing an empty lookup and a second create. Duplicates remain
  detectable by ticket markers; multiple matches during resolution keep
  `unknown` with `vault_marker_ambiguous`, without another create. There is no
  continuous duplicate scan after `done`. Keep keys and both databases until
  resolution, reconcile duplicates, and move items only for `done` tickets.
  Oversized listings fail closed with `vault_lookup_too_large`; raise the cap or
  empty/shrink the collection by moving only done-ticket items, never unresolved
  ones. Matching requires the exact ticket marker and at least one fingerprint
  field (text fields only), all of whose values equal the expected HMAC under the writer-only
  fingerprint key. A collection editor cannot derive that HMAC from the public
  ticket ID; without the key or a copied reference, forging it requires guessing
  the 64-bit value. A marker-only item never matches. Copying a genuine item's
  fingerprint for the same ticket means the secret was already stored, but does
  not prove the copy still contains it. Key holders, a compromised writer, and
  edits/deletion of genuine items remain outside this protection; shared web
  lifecycle state remains a separate trust boundary.
- **Mail API token compromise:** provision a token scoped to sending as the
  configured sender mailbox only, with allowlist-only recipient enforcement.
  Within that scope, theft enables sending mail as that mailbox to allowed
  recipients, including forged notifications; it does not confer vault access.
  These restrictions must be enforced by the mail service, not by intake.
- **Link interception before use:** the link is a bearer capability. Anyone who
  obtains it can open the form and win the single submission. Deliver privately,
  prefer a short TTL and watch completion/failure mail. Fingerprints are for
  operator-side matching of mail, CLI and vault records, **not recipient
  verification**. Recipients cannot compute them independently and must never
  receive the fingerprint key. Single use does not establish who supplied the
  value. A malicious recipient can submit a wrong value or intentionally consume
  the ticket; the operator must validate it.
- **Fingerprints and metadata:** names, purpose, times and fingerprints are
  visible in the shared database; target and recipient plaintext are writer-only
  and appear in metadata-only completion mail. Their shared unkeyed digest still
  permits offline guesses of predictable metadata. A fingerprint cannot be linked to a guessed value without the writer-only
  fingerprint key: copied mail or database records alone do not permit offline
  value guessing. Different ticket IDs produce different fingerprints even for
  the same key and value (subject to 64-bit collisions). Within one ticket,
  repeated computation with the same key and value is stable. The reference is
  not a signed attestation; a compromised web account can change the shared
  database's copy, and a vault editor can change custom fields. Previously issued
  value-only HMAC fingerprints still reveal cross-ticket equality; older unkeyed
  fingerprints retain their offline-guessing risk. Upgrading cannot retract old
  mail or backups. Do not put credentials into ticket metadata or target notes;
  use only the browser's secret-value input.
- **Browser compromise and denial of service:** malicious extensions, an infected
  recipient device, screenshots/clipboard history, flooding, and traffic analysis
  are outside the protection provided here. Rate limits are in memory, reset on
  restart, and are not a distributed abuse-prevention system. JavaScript strings
  cannot be reliably erased from process memory.
- Deleting keys/rows does not erase old backups, storage snapshots, or SSD history.
  Define backup access, retention, disk encryption, and master-key handling as
  part of deployment. Mail API acceptance also does not prove final delivery to
  a human inbox; monitor notification failures and delivery separately.

## Deployment (Docker/Portainer)

Use a Linux Docker Engine with Compose v2 or newer, local named-volume storage
suitable for SQLite WAL, and an existing trusted HTTPS tunnel connector. This
stack can run next to an existing Vaultwarden server; it does not deploy or expose
the vault server itself. The images pin Node `22.23.4-bookworm-slim` by digest and
`@bitwarden/cli@2026.10.0`. The bw build installs from committed
`docker/bw/package.json` and `package-lock.json` with
`npm ci --omit=dev --ignore-scripts`, including integrity-locked transitive
dependencies; it copies the complete installed tree into the runtime image.
The pinned CLI tree has no native addons; its only dependency lifecycle script
prints a core-js banner. The locked app dependency `better-sqlite3` 13.0.3 bundles
Linux x64/arm64 glibc prebuilds using Node-API 10, compatible with the pinned Node
22 and Bookworm runtime. It has no explicit `install` script or `prebuild-install`
download, but its `binding.gyp` triggers npm's implicit `node-gyp rebuild` install
step unless scripts are ignored. The app dependency stage therefore also uses
`npm ci --omit=dev --ignore-scripts`. Neither dependency stage installs a compiler
toolchain. The app dependency stage smoke-tests opening SQLite during the image
build to ensure the bundled prebuild actually loads; development dependencies
stay out of runtime images. Recheck prebuild/platform compatibility when updating
the lockfile or base image. No credentials are build arguments or image contents;
`.dockerignore` excludes secrets, environment files, data, tests, and nested local
`node_modules`, but retains the bw manifests.

A lockfile provides reproducibility, not a clean security audit. The pinned
CLI 2026.10.0 still requests `multer` 2.3.0, `node-forge` 1.4.0 and, through
`inquirer`/`external-editor`, `tmp` 0.0.33. `docker/bw/package.json` retains
targeted npm `overrides` for the fixable findings:

- `multer` 2.3.0 → 2.4.0, scoped to `@bitwarden/cli` (same major; the CLI and
  `@koa/multer` use the unchanged public API). The override also applies to
  `@koa/multer`'s shared dependency and removes the moderate `multer` advisory.
- `tmp` 0.0.33 → 0.2.7, scoped to `external-editor`, which only calls
  `tmpNameSync`. This clears the affected `tmp`, `external-editor`, and
  `inquirer` entries.

On 2026-10-19, with these overrides, `npm audit --package-lock-only` in
`docker/bw` reports **2 vulnerable package entries (2 high; 0 critical,
0 moderate, 0 low, 0 info)**: `node-forge` 1.4.0
([GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv), no
patched release exists) and its dependent `@bitwarden/cli`. These are one
underlying advisory, not two separate exceptions. The advisory concerns RSA
PKCS#1 v1.5 signature verification; the CLI uses node-forge only for AES
decryption, HMAC and hashes, not for RSA signature verification, and `bw serve`
has no published port; the writer is the only other service that mounts its
private Unix socket. CI's dependency audit covers both lockfiles; node-forge is
a documented, expiring exception scoped to `docker/bw` in
[`.audit-allowlist.json`](.audit-allowlist.json), expiring on **2027-01-19**.
The overrides pin versions outside the CLI's exact dependency pins, so
validate the vault service end to end (login, unlock, item creation in the
target collection through `bw serve`) after every change to `docker/bw`,
and drop overrides once a CLI release ships fixed versions.

Deploy `docker-compose.yml` as a **Portainer repository stack**, built directly
from the Git repository through each service's `build:` target; no registry or
locally prepared artifacts are required. Set variables from `.env.example` as
stack environment variables and point `*_PATH` secret variables at absolute paths
on the deployment host, prepared as described below. All build contexts are the
repository root and all COPY sources are committed and retained by `.dockerignore`.

From a clean checkout, without an `.env`, `node_modules`, or local secrets:

```sh
BW_ORGANIZATION_ID=build-placeholder BW_COLLECTION_ID=build-placeholder docker compose build
```

These two non-secret variables are required by Compose interpolation even for a
build; Portainer supplies the real stack values. Secret files are **runtime-only**
service mounts, not build secrets, arguments, or COPY inputs. They must exist with
the documented ownership/modes before stack creation/start. The static build tests
check this separation; actual Docker builds and version-specific Compose handling
of missing runtime-secret files must also be verified on the deployment host.
The systemd units under
[Non-Docker deployment prerequisites](#non-docker-deployment-prerequisites)
remain a supported alternative.

### Container boundaries and persistent state

- **web** runs as `10001:10001`, with supplementary group `10010`, and belongs
  only to the external `tunnel` network. The trusted connector joins that network
  and targets **`http://web:3000`** for `https://intake.example.com`. Web's only
  published host port is `INTAKE_WEB_BIND`, loopback-only by default (see
  [Host port binding](#host-port-binding)); `expose` is documentation, not an
  access-control rule.
- **writer** runs as `10002:10010`, with the shared socket group `10010`, and
  belongs only to the stack's `egress` bridge. It reaches the mail API via HTTPS
  and the unlocked local vault API via a private Unix socket, not a TCP port.
- **bw** runs as the **same `10002:10010` identity as writer**, with its own
  HOME/appdata volume, and belongs only to `egress` for vault-server HTTPS access.
  It neither mounts the ticket databases nor joins the web network.

All three have a read-only root filesystem, a `/tmp` tmpfs, all capabilities
dropped, `no-new-privileges`, an init process, and `restart: unless-stopped`.
Compose also bounds processes/threads and memory per service: web **64 PIDs /
256 MiB**, writer **128 PIDs / 512 MiB**, and bw **256 PIDs / 1 GiB**. These are
starting budgets, not a load-test result; monitor OOM/restart events and tune the
limits for collection size, traffic, and the vault account's unlock/KDF settings.
There is no runtime root/chown entrypoint. Do not scale writer or bw beyond one
instance or share their volumes with another deployment. Containers are not a
boundary against host root, Docker administrators, or a compromised writer UID.

| Named volume    | Mounted into                     | Contents and initial directory ownership/mode                                                       |
| --------------- | -------------------------------- | --------------------------------------------------------------------------------------------------- |
| `intake-sock`   | writer read/write; web read-only | `/run/intake`, `10002:10010`, `0770`; wake-up socket becomes `0660`                                 |
| `intake-shared` | web and writer read/write        | `/var/lib/intake/public`, `10002:10010`, `2770`; shared `tickets.sqlite` plus WAL/SHM               |
| `intake-writer` | writer only                      | `/var/lib/intake/private`, `10002:10010`, `0700`; private `keys.sqlite` plus WAL/SHM                |
| `bw-sock`       | bw read/write; writer read-only  | `/run/intake-bw`, `10002:10010`, `0700`; unauthenticated vault API socket                           |
| `bw-data`       | bw only                          | `/var/lib/intake/bw`, `10002:10010`, `0700`; dedicated CLI profile/cache and stored API credentials |

There are **two databases**, not a socket-only queue: web, writer, and DB-using
CLI commands share the writable ticket DB. Writer and CLI `create`/`purge` also
need the separate private DB containing encrypted private keys and trusted ticket
metadata. `docker compose exec writer ...` gives the CLI both mounts and its
required key-file configuration. Web never mounts `intake-writer`, `bw-sock`, or
`bw-data`, and receives no writer, mail, or vault credentials.

The Dockerfile creates the mount-point directories with these owners/modes at
build time. On the **first mount of a new, empty local named volume**, Docker's
normal volume population inherits this directory metadata. Both application
images contain matching shared-directory metadata. The writer's primary GID is
`10010`, so its socket gets the shared group even with parent mode `0770`; the
shared database directory additionally uses setgid `2770` for files created by
web. The private `0700` parents still exclude web despite that shared group.
Existing volumes are **not repaired** by rebuilding an image: inspect ownership
and provision/migrate them offline before starting. Do not add an unconditional
root startup script or weaken the writer's private vault-parent check.

The `egress` bridge uses the subnet `INTAKE_EGRESS_SUBNET`, default
**`10.200.176.0/24`**, instead of a Docker-assigned range, which can overlap the
host's LAN (e.g. a home router LAN in 192.168.x.0/24) and cut the host off from
it. Choose a subnet that overlaps no network the host must reach. Docker does not
change an existing network's subnet, so a changed value only applies once the
network is recreated. A Portainer Git redeploy usually recreates the network on
its own. If the subnet is still wrong afterwards (check under **Networks**), stop
the stack, remove the stack's `egress` network and redeploy. With plain Compose,
run `docker compose down` (without `-v`) before `up`.

The external network name comes from `INTAKE_TUNNEL_NETWORK`. Keep only web and
trusted tunnel connectors on it; do not attach unrelated services or the vault
API. Web has no application need for outbound Internet access, but a normal
Docker bridge/tunnel network is **not an outbound-deny firewall**. Similarly,
`expose` does not prevent host/network peers from reaching web. Verify the actual
network/firewall policy on the deployment host.

### Configure file secrets for a new deployment

Copy `.env.example` to `.env` and replace its non-secret placeholders: public
origin, vault URL, organization/collection IDs, mail URL/mailbox, notification
address, and the existing tunnel network's name. Use a canonical `VAULT_URL`
without a trailing slash. Compose maps it to `BW_SERVER` only in bw. The seven
`*_PATH` settings are **host paths**, not secret values; they select Compose
`secrets.file` sources. Containers receive explicit per-role settings and
`/run/secrets/*` mounts, never the whole `.env` file. The Node application does
not load `.env` itself. Non-Docker role examples remain below.

Create a dedicated vault account with access only to the intended organization
and collection, and obtain that account's personal API client ID/secret. Configure
the mail sender's send permission and recipient allowlist, including every
possible `--notify-email` recipient. Do not reuse a personal CLI profile.

**New deployment only.** In a private shell with tracing disabled, generate three
independent 32-byte base64 keys and create empty credential files. This deliberately
fails if the secrets directory already exists; do not rerun against existing keys.

```sh
(
  set -eu
  set -C
  umask 0077
  mkdir -m 0700 ./secrets
  for name in token_hmac_key writer_master_key fingerprint_key; do
    openssl rand -base64 32 > "./secrets/$name"
  done
  for name in mail_api_token bw_client_id bw_client_secret bw_master_password; do
    : > "./secrets/$name"
  done
)
```

All files are initially mode `0600`. Before changing their ownership, fill the
four empty files through a private editor: a mail bearer token, API client ID,
API client secret, and vault master password, respectively, each on one line.
Do not put these values in `.env`, commands, shell history, logs, or build args.
The password-file bootstrap intentionally stores a restricted master password
for unattended unlock; unlike the interactive host flow below, possession of it
and the CLI/API credentials can grant vault access. Protect these files and
`bw-data` as vault capabilities. Never commit them; `secrets/` is ignored by both
git and the image build.

**Local file-backed Compose secrets are bind mounts:** Compose's secret
`uid`/`gid`/`mode` options do not remap them. The application still requires
writer master/fingerprint/mail files to be owned by its runtime UID and exactly
`0600`. For a rootful daemon without user-namespace remapping, provision:

```sh
sudo chown 10002:10010 ./secrets/*
sudo chmod 0600 ./secrets/*
# The one shared-key exception: both distinct application UIDs must read it.
sudo chmod 0640 ./secrets/token_hmac_key
```

Keep `./secrets` itself private to its host administrator (`0700`). The HMAC
file's shared `0640` is intentional; every other credential stays `0600`.
Before any CLI call, the bw entrypoint checks all three vault secret files are
readable regular files with no group/other permission bits, using `stat -c %a`.
Owner-read-only `0400` is also accepted. Missing, unreadable, non-regular,
symlink, unsafe-mode, or failed-stat inputs exit with the same generic error,
without printing file paths or contents, even when reusing a logged-in profile.
For rootless Docker or user-namespace remapping, translate the container IDs to
host IDs and verify the resulting mounts from each container identity; do not
assume these host numeric IDs are correct or relax the application's checks.
Key loss/rotation consequences are the same as in the host setup below: never
regenerate keys during an ordinary rebuild, restart, or upgrade.

### First start and tunnel configuration

The connector's external network must already exist before `docker compose up`,
including when the connector only uses the host port: web stays attached to the
network named by `INTAKE_TUNNEL_NETWORK`. Create that network when it is not
already managed by your tunnel deployment, using the configured name, for
example `docker network create intake-tunnel`. Join the trusted connector to it
and configure the HTTPS route to `http://web:3000`, or, for a connector on the host
network, to `http://127.0.0.1:3093` (see [Host port binding](#host-port-binding)).
The web image explicitly sets `INTAKE_HOST=0.0.0.0` inside its network namespace;
the non-Docker application default remains `127.0.0.1`.

```sh
docker compose config --quiet
docker compose build --pull
# Validate the role-scoped secret mounts without starting either application:
docker compose run --rm --no-deps --entrypoint node web --input-type=module -e \
  'import { loadConfig } from "./src/config.js"; loadConfig();'
docker compose run --rm --no-deps --entrypoint node writer --input-type=module -e \
  'import { loadConfig } from "./src/config.js"; loadConfig(process.env, "writer");'
docker compose up -d --wait --wait-timeout 180
docker compose ps
```

bw configures the vault server on a fresh profile, reads API credentials only
for `bw login --apikey`, captures a fresh password-file unlock session without
printing it, and execs `bw serve` on the Unix socket. For a logged-in profile,
it checks the stored server instead of calling the setter (which the CLI rejects
while logged in), then unlocks again. A server mismatch fails closed; changing
accounts/server requires an explicit, carefully planned profile reset, not
silently reusing or deleting `bw-data`. bw may remove a **confirmed stale socket**
after a refused connection in its private parent, but refuses a live listener,
symlink, regular file, or unsafe parent. Never run competing bw instances.

Startup waits for bw's Unix `/status` response to report `unlocked`, then for
writer's empty `/healthz`, then starts web. Web's GET/HEAD `/healthz` returns
**204 with no data**, covering HTTP liveness only. Writer's probe confirms startup
permissions/recovery completed, not vault/mail availability; bw's probe checks
local unlocked status, not current remote reachability or synchronization.
Probes print no upstream bodies or secrets. Dependencies gate **Compose-managed startup**, not Docker Engine restarts or
continuous availability: Docker does not automatically restart an unhealthy
container or stop writer when bw later becomes unhealthy. The writer independently
claims each due pending ticket, checks private revocation, latches first sight and
enforces private expiry grace before checking local unlocked status, including
after a reboot. A failed readiness check requeues it as `pending` with
`failure_code=vault_unavailable`, incremented attempts and persisted backoff,
retaining ciphertext/key. Timely first sight lets retries survive expiry during
an outage. Terminal mail still proceeds. Preflight logs `vault_unavailable` once
on entry to an outage and `vault_available` once on recovery, not on every poll or
queued ticket; these
report local readiness, not remote-server availability. Socket preparation errors
include only a safe internal/system code, never paths or exception messages.
Sync/refresh failures before the item request and proven
zero-delivery connect failures preserve pending work with persisted bounded
backoff, including after a successful preflight. Ambiguous item writes become
`unknown`, retaining envelope/key without mail until delayed marker-based
resolution. Lookup failures remain `unknown`; they do not authorize a create.
Monitor health and safe errors, and pause writer before planned vault maintenance.

**API credential rotation is explicit.** A logged-in CLI profile retains its API
credentials in `bw-data`; changing mounted API files alone does not reauthenticate
that profile. Pause new submissions, drain existing work, and stop writer and bw.
Update the restricted files, then log out only this dedicated CLI profile:

```sh
docker compose run --rm --no-deps --entrypoint bw bw logout
docker compose up -d --force-recreate --wait --wait-timeout 180
```

Confirm logout succeeded before restarting. Recreation remounts replaced secret
files, and bootstrap logs in with the new credentials. Do not delete ticket
volumes or regenerate application keys for a vault-credential change. For an
account/server change, first reconcile all pending work and the intended target
collection; do not silently repurpose the existing profile. Local unlocked health
alone does not verify remote token refresh or collection access.

The compose stack sets `INTAKE_CLIENT_IP_HEADER=cf-connecting-ip` by default. This
is only safe while web is reachable **exclusively through the trusted tunnel
connector**, which removes/overwrites client-supplied copies. Network membership
alone is not that guarantee: verify host and peer access too, including local
processes that can reach the loopback `INTAKE_WEB_BIND` port. Otherwise set
`INTAKE_CLIENT_IP_HEADER=off` to disable it; clients could spoof their IP.
Do not enable `TRUST_PROXY` or pass arbitrary forwarding headers through. With
the header enabled, open/submit requests with a missing, invalid, or repeated
header return HTTP 400 `request_rejected`; local static/health probes do not need
it. Warnings are throttled as described in the reverse-proxy section below.
HSTS defaults to one year; if the tunnel/proxy sets it on all responses, set
`INTAKE_HSTS_MAX_AGE=off` here to avoid duplicates. Do not add caching, body/token
logging, or third-party scripts at the tunnel.

### Host port binding

`INTAKE_WEB_BIND` sets the host side of web's single published port,
`<host-address>:<host-port>`, mapped to container port `3000`. It lets a tunnel
connector that runs on the **host network** reach web without joining the
`tunnel` network. Web stays attached to the external tunnel network even when
the connector only uses the host port, so the network named by
`INTAKE_TUNNEL_NETWORK` must exist for `docker compose up`. The default is
**`127.0.0.1:3093`**: loopback only, reachable from the deployment host itself
but not from other machines. An empty or unset value uses this default.

```sh
# Default; the host-network connector targets http://127.0.0.1:3093
INTAKE_WEB_BIND=127.0.0.1:3093
# Different loopback port
INTAKE_WEB_BIND=127.0.0.1:8093
```

**Never set it to `0.0.0.0:<port>`, `[::]:<port>`, a bare port such as `3093`,
or a public interface address.** Docker then publishes web on every matching
interface, usually past the host firewall, and clients can bypass the tunnel and
spoof the client IP header. Even on loopback, any local process or user on the
host can reach web directly; treat host access as part of the client IP header
trust boundary above.

Docker Engine releases before 28.0.0 did not drop packets from hosts on the same
network segment addressed to ports published on `127.0.0.1`, so such a neighbor
could reach the loopback port (fixed in 28.0.0,
[moby/moby#49325](https://github.com/moby/moby/pull/49325)). Docker 28.2.0
through 28.3.2 could lose that protection after a firewalld reload
([CVE-2025-54388](https://github.com/advisories/GHSA-x4rx-4gw3-53p4), fixed in
28.3.3). Use Docker Engine 28.3.3 or later. Otherwise firewall the host so the
published port is unreachable from the network. Do not set
`DOCKER_INSECURE_NO_IPTABLES_RAW=1`; it disables this protection.

Compose cannot validate `INTAKE_WEB_BIND`. After the stack is up, check the
published address:

```sh
docker compose port web 3000
```

It must print `127.0.0.1:<port>`. If it shows `0.0.0.0`, `[::]`, or another
address, stop the stack and fix `INTAKE_WEB_BIND`.

### Operate, inspect, and upgrade

Run CLI commands inside writer, **without overriding its non-root user**:

```sh
docker compose exec writer node src/cli.js create \
  --key-name DB_PASSWORD --purpose "Set up the example application" \
  --target-item "Example application database" --target-field password \
  --ttl 24h --notify-email ops@example.com
docker compose exec writer node src/cli.js list
TICKET_ID=REPLACE_WITH_TICKET_ID
docker compose exec writer node src/cli.js show -- "$TICKET_ID"
docker compose exec writer node src/cli.js revoke -- "$TICKET_ID"
docker compose exec writer node src/cli.js notify-retry -- "$TICKET_ID"
docker compose exec writer node src/cli.js purge --older-than-days 30
docker compose logs --tail 100 web writer bw
```

`create` prints the complete link once to this private terminal, not container
service logs. Do not record or forward its stdout. `list` and `show` print only
summary metadata, notification status, a completion fingerprint, `attempts`, and
`failure_code` (`-` when absent), never values, tokens, or ciphertext. `show`
selects one ticket; there is no link recovery. A `ticket_stuck` warning calls for
inspection with `show`: check the failure code, vault credentials, collection
permissions, and connectivity. Persistent 400/403 responses still retry with
capped backoff; fix their cause rather than deleting recovery material or
reactivating the ticket. The warning is diagnostic, not a retry limit.
For `database_busy`, check local SQLite contention rather than vault permissions;
ticket material and the key are kept for the normal retry timers.
Compare completion mail, the CLI summary, and vault reference fields as described
below. `revoke`, `notify-retry`, and `purge` retain their existing safety limits.
If the writer is down for more than the **15-minute** grace after a ticket's
expiry, submissions made shortly before expiry are rejected with
`failure_code=ticket_expired` and their key is removed at the next prune.
Reissue the affected tickets.

For upgrades, pause the tunnel route/new submissions or stop web, let writer
finish accepted work and notifications, then stop writer **before bw**. Back up
`intake-shared` and `intake-writer` together while stopped, including SQLite WAL/SHM
if present, and preserve the secret files and restricted `bw-data` separately.
Do not back up/restore socket files. For this digest-AAD upgrade, revoke remaining
active tickets and reissue them after deployment; old envelopes and digest-less
tickets are not migrated. Follow the full older-AAD warning in the host
prerequisites, including coordinated CLI/web/assets/writer updates. Update the
checkout and review image-version changes, then:

```sh
docker compose build --pull
docker compose up -d --wait --wait-timeout 180
docker compose ps
docker compose logs --tail 100 web writer bw
```

Keep the existing volumes, key files, and Compose project name. **Never use
`docker compose down -v` as an upgrade/reset command**: it deletes persistent
state. A longer writer stop grace allows in-flight vault/mail operations to
finish. Interrupted processing becomes `unknown` with a fresh settle delay;
marker lookup precedes any further create. Operator reconciliation is still
needed for ambiguous duplicate markers or suspected late-arriving duplicates.
After an unclean kill, the non-root writer entrypoint probes its persistent
wake-up socket and removes only a confirmed stale socket in its exact
writer-owned `0770` parent. Web's mount is read-only; writer is the only service
with write access to this volume. The underlying application still refuses an
existing socket, and the entrypoint never unlinks a live listener, symlink, or
regular file. If preparation refuses a path, stop writer and investigate ownership
and competing processes; do not bypass it with an unconditional removal command.

Validate on the deployment host before production: actual image builds, first
volume population, non-root secret access, denied web access to private/vault
state, tunnel exclusivity, and vault/mail integration. The automated suite parses
Compose YAML and asserts hardening, network/mount/secret isolation, pinned images,
and local probe behavior (`node --test test/compose.test.js` for the static
checks); it does not replace a Docker build or a live deployment test.

## Non-Docker deployment prerequisites

Use a Linux host with systemd, local Unix sockets, persistent local storage
suitable for SQLite WAL, a trusted HTTPS reverse proxy, Node **22.18 or newer
within the 22.x line**, and the Bitwarden CLI compatible with the selected vault
server. The adapter uses the
CLI's Vault Management API, not the vault server's administrative API.

`mise.toml` pins Node 22 for development. Production units deliberately execute
`/usr/bin/node`; the installer must install Node **22.18+ from the 22.x line at
that exact path** (or edit every unit and CLI example consistently). The CLI uses
`import.meta.main`, which requires that minimum version. The units do not run `mise` or
inherit a developer shell's runtime. Check `/usr/bin/node --version` before
starting them. Install a compatible CLI **2025.10.0 or newer** at
`/usr/local/bin/bw` for Unix-socket `serve` support, and check its `--version`
and `serve --help` output. Native `better-sqlite3` installation may
require a compiler toolchain if a matching prebuilt binary is unavailable.

For an upgrade from older AAD formats (including the former six-element format
that exposed target and notification address), pause new submissions and let the
**old writer** drain all `pending`/`processing` work, resolve any `unknown`
work if supported by that version, and resolve outstanding notifications before
deployment. Revoke and reissue remaining active tickets.
Deploy CLI, web, browser assets, and writer together; have users open newly issued
links rather than submit from stale open forms. Preserve all application keys;
provision the separate fingerprint key only if upgrading from before it existed.

Schema upgrades automatically add nullable `meta_digest` columns to both databases,
but deliberately **do not backfill legacy tickets**, even when a private snapshot
exists: a digest cannot make an existing envelope compatible with the new
five-element AAD. Authorized open/submit requests for an otherwise active legacy
ticket return HTTP 409 `ticket_upgrade_required` without opening or consuming it.
A queued ticket missing either digest fails closed as `ticket_upgrade_required`,
without a vault write, and destroys its per-ticket key. A failure notification can
still go to the original address when a trustworthy private snapshot exists.
Older tickets missing the private snapshot altogether fail without a vault write
or mail, with notification error `private_metadata_missing`. Never backfill from
the web-writable database or reinterpret/rewrite old envelopes. These upgrade
requirements apply equally to Docker volumes and host installations.

### 1. Install application files

Install this checkout and its production dependencies in `/opt/intake`, with
root ownership and no write access for either service account. From the source
checkout, use the pinned runtime to install and verify first:

```sh
mise install
mise exec -- npm ci
mise exec -- npm run verify
```

For the installed copy, run `npm ci --omit=dev` with the production Node 22
runtime and ensure dependencies remain readable from `/opt/intake`. Do not run
service entrypoints as root: **web, writer, and CLI refuse UID 0**. Do not make the
application directory writable to service accounts just to install dependencies.

### 2. Create accounts, shared directories, and keys

The following administration commands assume `sudo`, standard account-management
tools, and a root-owned `/opt/intake` installation. Run account creation only once.
**For a new deployment only:** the key-file creation and generation commands
below overwrite existing files. Do not rerun them against existing ticket data.

```sh
sudo groupadd --system intake-sock
sudo useradd --system --user-group --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin intake-web
sudo useradd --system --user-group --no-create-home \
  --home-dir /var/lib/intake/bw --shell /usr/sbin/nologin intake-writer
sudo usermod --append --groups intake-sock intake-web
sudo usermod --append --groups intake-sock intake-writer

sudo install -d -o root -g root -m 0755 /var/lib/intake /etc/intake
sudo install -d -o intake-writer -g intake-sock -m 2770 /var/lib/intake/public
sudo install -d -o intake-writer -g intake-writer -m 0700 \
  /var/lib/intake/private /var/lib/intake/bw

sudo install -o intake-writer -g intake-sock -m 0640 /dev/null /etc/intake/hmac.key
sudo install -o intake-writer -g intake-writer -m 0600 /dev/null /etc/intake/writer.key
sudo install -o intake-writer -g intake-writer -m 0600 /dev/null /etc/intake/fingerprint.key
sudo -u intake-writer /bin/sh -c \
  'set -eu; umask 0077; openssl rand -base64 32 > /etc/intake/hmac.key; openssl rand -base64 32 > /etc/intake/writer.key; openssl rand -base64 32 > /etc/intake/fingerprint.key'
```

Generate each key only once: replacing the HMAC key invalidates outstanding
links; replacing or losing the writer master key makes existing encrypted
private keys unusable. Replacing the fingerprint key changes future fingerprints
and prevents direct comparison to old ones. Never reuse the token HMAC or writer
master key as the fingerprint key. There is no automatic key-rotation/migration facility.
Back up keys only through an appropriately restricted secret-management process.

Required ownership and permissions:

| Path                                    | Owner:group                            | Mode                | Purpose                                             |
| --------------------------------------- | -------------------------------------- | ------------------- | --------------------------------------------------- |
| `/opt/intake`                           | `root:root`                            | root-writable only  | Code and production dependencies                    |
| `/var/lib/intake/public`                | `intake-writer:intake-sock`            | `2770`              | Public SQLite, WAL, SHM; both roles must write      |
| `/var/lib/intake/public/tickets.sqlite` | creating service account:`intake-sock` | `0660`              | Shared ticket state                                 |
| `/var/lib/intake/private`               | `intake-writer:intake-writer`          | `0700`              | Private SQLite and its WAL/SHM                      |
| `/var/lib/intake/private/keys.sqlite`   | `intake-writer:intake-writer`          | `0600`              | Encrypted PKCS8 keys                                |
| `/var/lib/intake/bw`                    | `intake-writer:intake-writer`          | `0700`              | CLI configuration and cached encrypted vault data   |
| `/etc/intake/hmac.key`                  | `intake-writer:intake-sock`            | `0640`              | Shared HMAC authorization key                       |
| `/etc/intake/writer.key`                | `intake-writer:intake-writer`          | `0600`              | Writer AES-GCM master key                           |
| `/etc/intake/fingerprint.key`           | `intake-writer:intake-writer`          | `0600`              | Independent writer-only fingerprint HMAC key        |
| `/etc/intake/mail.token`                | `intake-writer:intake-writer`          | `0600`              | Mail API bearer credential                          |
| `/run/intake`                           | `intake-writer:intake-sock`            | `2770`              | Shared Unix socket parent                           |
| `/run/intake/writer.sock`               | `intake-writer:intake-sock`            | `0660`              | Writer wake-up and notification retry               |
| `/run/intake-bw`                        | `intake-writer:intake-writer`          | `0700`              | Writer-only vault socket parent, created by systemd |
| `/run/intake-bw/bw.sock`                | `intake-writer:intake-writer`          | Protected by parent | Unauthenticated vault API, inaccessible to web      |

The public directory must be **group-writable**, not merely group-readable:
SQLite WAL creates and updates sibling `-wal` and `-shm` files. Setgid `2770`
keeps the `intake-sock` group on new files, and all public-database processes
must use umask `0007` (the entrypoints and supplied units do). The private parent
is `0700` even if a sidecar inherits broader mode bits. Do not put the public
database in a read-only web mount. The HMAC secret-file check permits group
access but rejects permissions for other users. Master-key, fingerprint-key and
mail-token files must be owned by the running UID and have mode `0600`; missing,
wrong-owner, overly open or invalid fingerprint files prevent writer startup.

### 3. Supply separate environment files

`.env.example` is the **Docker Compose interpolation template**, not a host
service environment file. **The application does not load `.env` automatically.**
For a non-Docker installation, use the separate per-role systemd `EnvironmentFile`
examples below, or explicitly supply the environment when invoking a process.
Never pass a combined environment, writer environment, master key, mail token,
or session key to the web process.

Create the role files before editing them:

```sh
sudo install -o root -g intake-sock -m 0640 /dev/null /etc/intake/web.env
sudo install -o root -g intake-writer -m 0640 /dev/null /etc/intake/writer.env
sudo install -o intake-writer -g intake-writer -m 0600 /dev/null /etc/intake/bw.env
sudo install -o intake-writer -g intake-writer -m 0600 /dev/null /etc/intake/mail.token
sudoedit /etc/intake/web.env /etc/intake/writer.env /etc/intake/mail.token
```

`/etc/intake/web.env` contains only public-role settings:

```dotenv
INTAKE_DB=/var/lib/intake/public/tickets.sqlite
INTAKE_SOCKET=/run/intake/writer.sock
INTAKE_HMAC_KEY_FILE=/etc/intake/hmac.key
INTAKE_PUBLIC_URL=https://intake.example.com
INTAKE_MAX_TTL=7d
PORT=3000
INTAKE_HSTS_MAX_AGE=31536000
TRUST_PROXY=false
# Only behind an exclusive, trusted proxy that overwrites this header:
# INTAKE_CLIENT_IP_HEADER=cf-connecting-ip
```

`/etc/intake/writer.env` has the shared values plus private configuration:

```dotenv
INTAKE_DB=/var/lib/intake/public/tickets.sqlite
INTAKE_SOCKET=/run/intake/writer.sock
INTAKE_HMAC_KEY_FILE=/etc/intake/hmac.key
INTAKE_PUBLIC_URL=https://intake.example.com
INTAKE_MAX_TTL=7d
INTAKE_DEFAULT_NOTIFY_EMAIL=ops@example.com
INTAKE_PRIVATE_DB=/var/lib/intake/private/keys.sqlite
INTAKE_WRITER_KEY_FILE=/etc/intake/writer.key
INTAKE_FINGERPRINT_KEY_FILE=/etc/intake/fingerprint.key
INTAKE_POLL_MS=1000
INTAKE_VAULT_RETRY_BASE_MS=5000
INTAKE_VAULT_RETRY_MAX_MS=300000
INTAKE_STUCK_ATTEMPTS=10
INTAKE_UNKNOWN_SETTLE_MS=120000
INTAKE_NOTIFY=on
MAIL_API_URL=https://mail.example.com
MAIL_API_MAILBOX=intake@example.com
MAIL_API_TOKEN_FILE=/etc/intake/mail.token
INTAKE_BW_SOCKET=/run/intake-bw/bw.sock
BW_ORGANIZATION_ID=REPLACE_WITH_ORGANIZATION_ID
BW_COLLECTION_ID=REPLACE_WITH_COLLECTION_ID
BW_SYNC_BEFORE_WRITE=true
BW_MAX_RESPONSE_BYTES=1048576
```

Replace both vault identifier placeholders, and place only the actual bearer
credential on one line in `/etc/intake/mail.token`. Do not put credentials on
command lines or in source control. The writer refuses startup without mail
configuration unless `INTAKE_NOTIFY=off` is explicitly selected for development.
Even with mail disabled, ticket creation still requires a notification address.
Keep all shared values consistent between services and CLI.

Configure `MAIL_API_MAILBOX` as an **allowlist-only sender mailbox** in the mail
service, with a token permitted to send as that mailbox. **Every notification
recipient** must be on that mailbox's recipient allowlist, including
`INTAKE_DEFAULT_NOTIFY_EMAIL` and any per-ticket `--notify-email` address. A
syntactically valid address in intake is not mail-service authorization. Verify
the allowlist and send permission before enabling production notifications.
HTTP `403 recipient_not_allowed` or `403 send_not_allowed` is terminal for the
notification, with no automatic retry; fix the allowlist or send permission (or
the underlying code/configuration fault) before a manual `notify-retry`.

For the CLI helper below, keep `writer.env` simple shell-compatible `NAME=value`
assignments as well as valid systemd environment-file syntax: no `export`, shell
substitutions, or untrusted content. Both files should contain paths rather than
raw credential values. The session goes only in `bw.env`.

### 4. Prepare the dedicated vault account and unlocked local API

1. Create a dedicated service account in the vault and a dedicated **Intake**
   collection in the intended organization. Grant that account access only to
   that collection, including permission to create entries. Record the
   organization ID and collection ID in `writer.env`; names are not IDs.
2. Confirm the account can create and read entries in this collection, and cannot
   access unrelated collections. A human with the necessary organization access
   later moves entries out **only after their tickets are `done`**, so unresolved
   writes remain visible to marker recovery. Keep this dedicated collection small
   enough for a full listing within `BW_MAX_RESPONSE_BYTES`. Do not advertise a
   stronger collection security boundary than the vault provides.
3. Log in and unlock interactively under the **same account and data directory**
   used by the service. Do not use a personal vault account or an administrator's
   existing CLI profile. Keep master passwords out of shell history and files.

```sh
sudo -u intake-writer /usr/bin/env \
  HOME=/var/lib/intake/bw \
  BITWARDENCLI_APPDATA_DIR=/var/lib/intake/bw \
  /bin/sh
```

In that private interactive shell:

```sh
umask 0077
/usr/local/bin/bw config server https://vault.example.com
/usr/local/bin/bw login
if ! BW_SESSION="$(/usr/local/bin/bw unlock --raw)" || [ -z "$BW_SESSION" ]; then
  printf '%s\n' 'Unlock failed; do not start the services.' >&2
  exit 1
fi
export BW_SESSION
/usr/local/bin/bw sync
/usr/local/bin/bw status
# Confirm the reported status is unlocked and the intended account is active.
printf 'BW_SESSION=%s\n' "$BW_SESSION" > /etc/intake/bw.env
unset BW_SESSION
exit
```

Do not enable shell tracing or record this shell session. `bw.env` contains an
unlocked session capability and must remain writer-owned `0600`. If your CLI
release prompts differently, follow its installed help and obtain a fresh
session through its supported unlock flow; do not persist a master password to
avoid the prompt. Account API-key login, when used, still requires unlocking
before encrypted items can be created.

The example unit runs as `intake-writer`, with systemd
`RuntimeDirectory=intake-bw` and `RuntimeDirectoryMode=0700`:

```text
/usr/local/bin/bw serve --hostname unix:///run/intake-bw/bw.sock
```

`INTAKE_BW_SOCKET=/run/intake-bw/bw.sock` is intake's default, including when
neither transport setting is supplied. The CLI's Unix-socket support was added
in [bitwarden/clients#14262](https://github.com/bitwarden/clients/pull/14262)
and released in CLI 2025.10.0. The CLI also supports `fd+listening://3` for
systemd socket activation; the supplied unit instead lets `bw serve` create the
socket directly. The web account cannot traverse its writer-owned `0700` parent.
Do not share this parent with the separate group-accessible writer wake-up socket.
Vault socket paths must be absolute and at most **103 UTF-8 bytes**, not 103
characters. This portable bound prevents Node from silently truncating a path
and connecting outside the parent that was permission-checked. Configuration,
adapter construction and the startup access check all reject longer paths.

Unix requests send HTTP `Host: localhost:8087`, which is accepted by the CLI's
Host allowlist with its default logical port. Keep `bw serve`'s port option at
its default `8087` in Unix mode too; that authority does not open a TCP listener.
CLI 2026.6.0+ validates Host even over Unix sockets and rejects bare `localhost`.
Origin protection stays enabled, and intake sends no Origin header. Explicit
TCP mode instead derives Host from the configured loopback URL.

It receives `BW_SESSION` through `/etc/intake/bw.env` and uses
`BITWARDENCLI_APPDATA_DIR=/var/lib/intake/bw`. Intake does not log in, unlock,
launch, or renew the vault CLI. If the CLI is locked, logged out, or its session
is invalidated, stop the intake writer, obtain a fresh session, restart the
local API, verify readiness, and then start the writer. Do not assume the
session remains usable after an operator locks the vault or changes credentials.

**The API has no authentication.** Anything running as the writer UID or root
can use the unlocked vault; Unix-socket permissions do not isolate processes
sharing that UID. Never expose the socket through a proxy or forward it elsewhere.

Loopback TCP is an explicit fallback only: unset `INTAKE_BW_SOCKET`, set
`INTAKE_BW_URL=http://127.0.0.1:8087`, and change the CLI unit to
`bw serve --hostname 127.0.0.1 --port 8087`. Setting both intake transport
variables is a configuration error. The old `BW_SERVE_URL` setting is no longer
used; migrate it to the new settings. TCP mode emits event `vault_tcp_warning`
with safe code `vault_tcp_local_users`, without addresses or configuration values.
Any local user can reach that port unless an external policy prevents it. Never
bind it to a public interface, expose it through a reverse proxy, or forward it
to another host. As a TCP-only fallback, an administrator can use an nftables
output policy based on `meta skuid` to permit only the writer UID to connect to
the configured loopback vault port; account for IPv4 and IPv6 and verify both
allowed and denied identities. A network namespace is another external option.
These policies are not installed or enforced by intake and do not constrain root.
Preserve the writer's HTTPS mail access and the CLI's vault-server access; a
blanket network deny or `PrivateNetwork` on only one process breaks dependencies.

### 5. Install and start systemd units

Install the supplied units and tmpfiles rule:

```sh
sudo install -o root -g root -m 0644 /opt/intake/docs/intake-tmpfiles.conf \
  /etc/tmpfiles.d/intake.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/intake.conf
sudo install -o root -g root -m 0644 /opt/intake/docs/bw-serve.service \
  /opt/intake/docs/intake-writer.service /opt/intake/docs/intake-web.service \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/bw-serve.service \
  /etc/systemd/system/intake-writer.service /etc/systemd/system/intake-web.service
sudo systemctl start bw-serve.service
```

Before starting the writer, verify through the installed CLI/API's status
operation that the running local API is ready and **unlocked**, using a private
administrative terminal. Do not probe by submitting a real secret. Then:

```sh
sudo systemctl start intake-writer.service intake-web.service
sudo systemctl status bw-serve.service intake-writer.service intake-web.service
sudo systemctl enable bw-serve.service intake-writer.service intake-web.service
```

`After=` orders process startup; it does **not** establish that the CLI API is
ready. Validate startup/reboot behavior with the deployed CLI version and add a
version-appropriate readiness gate before allowing unattended processing.
Similarly, `Requires=` does not itself renew an invalid session or restore
readiness. The units are examples to validate in the target systemd version,
not a claim of a fully automated vault-unlock service.

The units use `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, restricted address families, and narrowly scoped
`ReadWritePaths`. `/opt/intake` and `/etc/intake` are read-only inside them.
Only the public database and wake-up socket directories are writable for web;
only public/private databases and the wake-up socket directory are writable for
the writer; only its own CLI data and runtime socket directories are writable for
`bw serve`. The writer can connect to the vault socket without writing its parent.
The writer-owned `0700` vault runtime directory, not loopback networking, blocks
web access to the default API. Outbound HTTPS intentionally remains possible.

`/run/intake` is created as `intake-writer:intake-sock` mode `2770` by tmpfiles,
**not by the web unit's `RuntimeDirectory`**. Stopping or restarting web must not
remove a live writer socket. Both application services use umask `0007`; the
writer creates the socket as `0660`. The CLI service uses `0077` for its own data.

The writer deliberately refuses to unlink a pre-existing socket: it might
belong to another live writer. After an unclean kill, an operator may need to
stop the writer, verify that no process is listening on or owns the socket,
remove **only the confirmed stale** `/run/intake/writer.sock`, and start it again.
Never add an unconditional socket-removal startup command or run two writers
against the same databases. Check the journal for sanitized startup or work
failure events; it intentionally will not print upstream error bodies.

### 6. Configure the HTTPS reverse proxy

Publish `https://intake.example.com` at the origin root and proxy it to
`http://127.0.0.1:3000`. Web does not terminate TLS and does not support mounting
under a URL prefix. Serve the application's headers unchanged; do not add
third-party scripts, request-body logging, URL-token transformations, response
caching, or pages that embed the service. A normal page GET must not call the
open or submit APIs. GET/HEAD `/healthz` returns an empty HTTP `204` with the
normal security headers. It checks HTTP liveness, not database, writer, vault,
or mail readiness; it exposes no status details or ticket data.

All responses, including static files, API responses, errors, and 404s, carry
this exact `Content-Security-Policy` value:

```text
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'
```

They also carry `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and
`X-Content-Type-Options: nosniff`. Keep scripts and styles in same-origin files:
no inline scripts, styles, event handlers, or `style` attributes, and no external
fonts, assets, CDNs, or tracking. Inline SVG markup and data images are allowed.

By default all responses also carry
`Strict-Transport-Security: max-age=31536000; includeSubDomains`, including static/HEAD responses,
API success, errors, 404s, rate-limit responses, and HTTP parser/expectation errors.
`INTAKE_HSTS_MAX_AGE` configures a nonnegative whole number of seconds; `0` or
`off` omits the header here (it does **not** send `max-age=0` or clear an already
cached browser HSTS policy). If the HTTPS reverse proxy sets HSTS instead, disable
it here to avoid duplicate headers and ensure the proxy covers its own errors as
well. Browsers honor HSTS only over HTTPS, not the internal loopback HTTP hop.
`includeSubDomains` applies only to subdomains of the intake host itself, not to
the parent domain or sibling hosts. For `intake.example.com`, it covers hosts such
as `files.intake.example.com`, but not `example.com` or `mail.example.com`, so it
is enabled by default. Set `INTAKE_HSTS_INCLUDE_SUBDOMAINS=false` if a subdomain of
the intake host must stay plain HTTP; responses then carry only `max-age=N`.
`preload` is never added: preloading is a separate, deliberate domain-wide decision.

Leave `TRUST_PROXY=false` unless a trusted proxy is the only route to web and
you configure it to overwrite `X-Forwarded-For` with the actual client address.
When enabled, intake uses the last header element, if it is a valid IP address;
it does not scan backward for another valid element. Do not pass arbitrary
client-supplied forwarding headers through unchanged. Without this
configuration, all proxied clients can share the loopback rate-limit bucket.

Alternatively, set `INTAKE_CLIENT_IP_HEADER=cf-connecting-ip` (or another valid
HTTP header name) for a proxy that supplies one client IP in that header. Header
names are case-insensitive; an unset setting or `off` (any case, surrounding
whitespace ignored) disables this switch. Empty or whitespace-only values stop
startup with `invalid_intake_client_ip_header` instead of silently grouping all
tunnel users into one socket-IP bucket.
**Enable it only when web is reachable exclusively through that trusted proxy**,
for example through a tunnel connector with no direct route to web. The proxy
must remove/overwrite client-supplied copies of the configured header. If clients
can reach web directly or pass their own header through, they can spoof their IP
and evade per-IP limits. This switch does not authenticate the requester.

The configured header **takes precedence over `TRUST_PROXY` and
`X-Forwarded-For`**, including on failure: exactly one header field containing
one IPv4 or IPv6 address must pass `net.isIP` after trimming surrounding whitespace.
For `/api/open` and `/api/submit`, lists, repeated fields, ports and invalid/missing
values fail closed with HTTP 400 `request_rejected`, without reading the body or
opening/claiming a ticket. There is no fallback to the socket address or
`X-Forwarded-For`: a missing trusted-tunnel header indicates direct or misrouted
traffic, and fallback would group all legitimate clients into one proxy bucket.
Rejections emit `client_ip_header_warning` at most once per minute per process
per safe code (`invalid_client_ip_header` or `missing_client_ip_header`), using a
monotonic clock; no header name, header value or IP is logged. Static assets and
`/healthz` do not require this header, so local health checks still work.
Without this switch, the existing socket/`TRUST_PROXY` behavior is unchanged.

An optional access proxy can be introduced externally later; this application
does not perform identity assertions or authenticate the link recipient.

## CLI reference

The package exposes an `intake` bin when installed that way. The explicit
entrypoint is `/usr/bin/node /opt/intake/src/cli.js`; it is not a root command.
Run `create` and `purge` as **intake-writer**, because both need access to the
private key store and master-key configuration. `list`, `show`, and `revoke` require only
the public database/HMAC environment; `notify-retry` uses only a request to the
writer socket after loading public-role configuration. None requires granting
the web process private credentials.

For the installed example, define this helper in a private administrative shell:

```sh
intake() {
  sudo -u intake-writer /bin/sh -c '
    set -a
    . /etc/intake/writer.env
    set +a
    umask 0007
    exec /usr/bin/node /opt/intake/src/cli.js "$@"
  ' intake "$@"
}
```

The helper sources the protected configuration **as the writer account**, then
executes the non-root CLI. Do not enable tracing, redirect creation stdout into
logs, or source untrusted environment files. This convenience uses writer
configuration for all commands; a least-privilege `list`/`show`/`revoke` operator can
instead receive only the public-role environment and public database access.

### Create

```sh
intake create \
  --key-name DB_PASSWORD \
  --purpose "Set up the example application" \
  --target-item "Example application database" \
  --target-field password \
  --target-notes "For the example application" \
  --ttl 24h \
  --notify-email ops@example.com
```

Required flags are `--key-name`, `--purpose`, `--target-item`, and
`--target-field`. `--target-notes`, `--ttl`, `--notify-email`, and
`--keep-whitespace` are optional. The notification recipient falls back to
`INTAKE_DEFAULT_NOTIFY_EMAIL`; creation fails if neither supplies a single plain
address. Commas, line breaks, display names, and lists of addresses are not
accepted. The chosen address must also be on the sender mailbox's allowlist.

`--keep-whitespace` is a boolean presence flag, with no value argument. By default
it is absent and the ticket stores `trim=true`: browser encryption removes
leading/trailing whitespace and line breaks using `String.prototype.trim()`
semantics. Adding `--keep-whitespace` stores `trim=false` and preserves the exact
supplied value, including nonempty whitespace-only values. For example:

```sh
intake create \
  --key-name EXACT_VALUE \
  --purpose "Collect a value whose surrounding whitespace is significant" \
  --target-item "Example application" \
  --target-field password \
  --keep-whitespace
```

The flag changes only the value policy, not metadata validation. An empty value
(zero length after applying the ticket's policy) is always invalid. The flag is
returned by `/api/open` as boolean `trim` and authenticated in the encrypted
envelope's AAD; it is not a recipient-selectable UI option.

TTL defaults to `24h` and accepts positive whole-number minutes, hours, or days,
for example `30m`, `24h`, or `7d`. It must not exceed `INTAKE_MAX_TTL` (default
`7d`); the default `24h` must also fit the configured maximum. Extending the TTL
does not permit multiple uses. Output is only the new link, once:

```text
https://intake.example.com/#req=<id>.<secret>
```

Deliver it through a private channel without link-preview tools that might run
interactive page actions. Metadata is plain text: maximum lengths are key name
128, purpose 1,000, item 256, field 128, and notes 4,000 JavaScript characters.
Do not supply an explicitly empty notes flag; omit it when there are no notes.
Never put the secret value in a CLI flag or metadata.

### Vault target mapping

The per-ticket target is generic `{ item, field, notes }`; organization and
collection come only from writer configuration. CLI creation saves the target,
notification address, digest and all other AAD fields in writer-only storage.
Only the digest and public display/AAD fields are also stored in the shared ticket
database. `/api/open` returns only the digest in place
of target and recipient details; the browser does not receive their plaintext.
The digest is unkeyed and not encryption: guessable metadata can still be tested
offline against it. Do not put secrets into target notes. The writer always uses
its own snapshot and recomputes its digest, never trusting the shared digest.
`BwServeAdapter` currently maps exact lowercase `username` or `password` fields to a new login item with
that one credential set. Any other field name produces a new secure note with
a hidden custom field of that name. Every item also has visible text reference
fields named `intake_ticket_id` and `intake_fingerprint` by default, for operator
comparison to completion mail and `intake list`. If the literal secret target
matches either reference name, only that reference moves to the corresponding
`intake_ticket_id_reference` or `intake_fingerprint_reference` field. The secret
keeps its exact original name and hidden type; field names remain unique. This
reference-field mapping needs no target rewrite for active or queued digest-bound
tickets targeting either name. It does not remove the separate digest-AAD upgrade
requirement to drain/reissue tickets from older formats.
`target.item` is the new item's name and `target.notes` becomes its notes.
This **creates a new item**, not an update or lookup of an existing item by
name. Initial creation optionally synchronizes first, then posts the encrypted-item
operation through the CLI API with the configured organization ID and collection
ID. Recovery of `unknown` is different: it always synchronizes, then lists the
configured collection without `search` and requires the exact ticket marker plus
at least one fingerprint field whose values all equal the expected fingerprint,
using the same collision-aware reference names and counting only text fields
(`type === 0`). A marker-only item never matches.
A uniquely matching item completes the ticket without another create; only a
complete, empty matching result authorizes one create attempt. See
[crash recovery](#crash-recovery-and-ambiguous-vault-writes) for ambiguity, size
limits, and residual duplicate risk. The CLI performs organization-key encryption
client-side. Validate behavior against your chosen CLI/server release before
production; fake-HTTP adapter tests are not live-vault certification.

### List, show, revoke, and retry notification

```sh
intake list
# Set TICKET_ID to the id shown by list, not the complete link/token.
TICKET_ID=REPLACE_WITH_TICKET_ID
intake show -- "$TICKET_ID"
intake revoke -- "$TICKET_ID"
intake notify-retry -- "$TICKET_ID"
```

- `list` prints ID, key name, lifecycle status (including unresolved `unknown`),
  expiry, notification status, fingerprint (`-` until a successful completion),
  `attempts`, and `failure_code` (`-` when absent); never values, tokens, or creation
  links. An expired active ticket displays as `expired` without needing a
  background expiry job.
- `show <id>` prints the same summary for one ticket, including derived expiry,
  completion fingerprint, `attempts`, and `failure_code`, without parsing or
  exposing queued ciphertext.
  A missing ticket returns `ticket_unavailable`; it cannot recover the link.
- `revoke` applies only to active tickets, preventing future open/submit. It
  cannot cancel pending/processing/unknown work or undo a stored vault entry.
  It asks the writer to latch revocation privately and remove the encrypted key
  immediately, without requiring private database access for the operator. If the
  writer cannot be reached, the CLI still exits successfully and reports deferred
  removal at the next writer prune (normally within **60 seconds** while running,
  or at startup). Private revocation persists even if shared state is later reset.
  If the writer reports that the shared row is no longer revoked, it did not
  remove the private key; the CLI reports that and exits non-zero. Inspect the
  ticket with `show`.
- `notify-retry` requests a retry **only for a failed notification** on a terminal
  `done` or `failed` ticket. It queues work over the Unix socket and returns
  before mail completion. It does not decrypt a value, create a vault item,
  replay a vault write, or make a consumed ticket usable. Check `list` afterward.
  A running, reachable writer is required. Fix the underlying failure before
  retrying: for `recipient_not_allowed` or `send_not_allowed`, correct the sender
  mailbox's recipient allowlist, send permission, or relevant code/configuration
  first. Retrying unchanged authorization cannot succeed. Ordinary processing is
  poll-backed; an unsuccessful manual retry request must be issued again after
  fixing IPC.

Lifecycle statuses are `active`, `pending`, `processing`, `unknown`, `done`,
`failed`, and `revoked`, with `expired` as the list-time view of an expired active
ticket. `unknown` is nonterminal accepted work awaiting delayed marker resolution;
it cannot be reopened, resubmitted, revoked, or purged. Notification states are
unset before terminal work (including while `unknown`), then `pending`, `sent`,
or `failed`. Safe details are stored as `notify_attempts`, `notify_error`, and
`notified_at`; `list` intentionally shows only the notification status. Writer-private
revocation or late first sight fails processing with `failure_code=ticket_revoked`
or `failure_code=ticket_expired`, respectively, without a vault write.

### Retention and purge

```sh
intake purge
intake purge --older-than-days 30
intake purge --older-than-days 0
```

`--older-than-days` is a nonnegative integer, default **30**; zero is allowed.
The cutoff is current time minus that many days. Expired active tickets are
eligible only when their expiry precedes the cutoff; `done`, `failed`, and
`revoked` tickets are eligible only when their terminal completion time precedes
it. Pending/processing/unknown work and terminal tickets with **pending
notification** are skipped, even at zero days. Failed notifications are not pending and can be
purged after the cutoff; resolve them first if another notification is needed.

Purge removes eligible public rows and their encrypted private keys, then prunes
orphaned and terminal keys regardless of the public row's age. The writer also
prunes keys at startup and every **60 seconds** by default: it latches observed
shared revocations privately and removes those keys, terminal residual keys, and
keys never seen submitted before private expiry plus the **15-minute** grace.
Normal writer processing deletes its key on terminal completion. Private metadata
survives key destruction until public purge, preserving notification retries;
failed creation and orphan cleanup remove both key and metadata.

Interrupted `processing` becomes `unknown` with a fresh settle delay. Once the
writer has seen submitted work in time, pruning retains its key while shared
status is pending/processing/unknown, even after expiry, for retries and eventual
lookup. Retain the original writer master and fingerprint keys too. Older tickets
without private expiry retain their keys until terminal cleanup or purge.

Automatic key pruning does **not** purge public rows. Arrange a protected operator
job running this CLI as the writer account if scheduled row retention is required.
Purge does not remove entries already stored in the vault or mail already sent.

## Notifications

The writer sends metadata-only ping mail through an HTTP API, not SMTP:

```text
POST ${MAIL_API_URL}/v1/mailboxes/${encodeURIComponent(MAIL_API_MAILBOX)}/send
Authorization: Bearer <token>
Content-Type: application/json

{"to":["ops@example.com"],"subject":"...","text":"..."}
```

Mail includes ticket ID, key name, purpose, ISO UTC completion time, fingerprint,
and target item/field. It contains **no value, link token, ciphertext, or target
notes**. After completion, the operator finds the ticket ID in `intake list` and
compares its fingerprint with the completion mail and the vault item's
visible `intake_ticket_id` / `intake_fingerprint` reference fields (use the
corresponding `_reference` name if it collided with the secret target, as
described above). Do not compare against the hidden secret field. All three
should refer to the same ticket and fingerprint. A mismatch requires investigation before moving
or using the entry; do not ask the recipient to compute or verify this reference.
It matches processing records, not the correctness of the submitted credential
or the recipient's identity. Move an entry out of the dedicated collection only
when its ticket is `done`; unresolved `unknown` items must remain visible for
lookup. Failure mail reports only safe terminal failure information and no
successful-completion fingerprint. Ambiguous writes stay `unknown` with no mail
until terminal resolution; a unique marker-and-fingerprint match completes and
notifies as usual.
Because the mail service may reject
credential-looking text with `422 secret_detected`, keep metadata descriptive
and credential-free. No upstream response body is logged or recorded in
`notify_error`; only safe error codes are retained.

The mail service is configured **allowlist-only**: every notification recipient
must be on the configured sender mailbox's recipient allowlist. HTTP `403` with
recognized code `recipient_not_allowed` or `send_not_allowed` is terminal, with
**no automatic retries**. The writer records `notify_status=failed` and the
corresponding safe code in `notify_error`. A successfully written vault item
stays `done`; notification failure neither rolls it back nor replays the write.
Fix the allowlist, send permission, or underlying code/configuration problem
before issuing a manual `notify-retry`.

A 2xx response normally counts as API acceptance (`sent`), not final mailbox
delivery. An explicit nonempty `rejected` response array is instead recorded as
a permanent failure with safe code `rejected`, even on 2xx. Success response bodies
are capped at **16 KiB**; exceeding this byte cap records `notify_status=failed`
with safe code `response_too_large` and is **not retried automatically**. A 2xx
response may already mean the mail was accepted, so investigate before making a
deliberate manual retry to avoid duplicate mail.
The default timeout is 10 seconds **per attempt**. There are at most two retries
(three total attempts per delivery cycle), with default 1- and 3-second backoffs,
only for network failures, timeouts, HTTP 429, and HTTP 5xx. All other 4xx
responses are permanent failures for that cycle and retain `http_<status>`
(e.g. `http_422`, or `http_403` for an unrecognized 403 code); only the recognized
403 cases above use their named safe codes. Other short error codes include
`http_503` and `timeout`. A manual retry creates a new delivery cycle; attempt
counts accumulate. A single notification worker delivers the persisted pending
queue independently of ticket processing, so slow mail does not delay vault work.
Shutdown stops new vault work and notification deliveries without draining the
backlog. It waits up to `INTAKE_SHUTDOWN_WAIT_MS` (default **5000 ms**) for the
in-flight delivery to settle and records its result normally. `0` cancels
immediately. Anything unfinished at the deadline is cancelled, stays pending,
and is re-sent after restart; late results are ignored. Startup recovers pending
notifications, not terminal failed notifications. Delivery remains **at least
once**: mail can be duplicated after a crash or an interrupted shutdown.
Keep this wait well below the container stop grace period (Compose writer
`stop_grace_period: 90s`) and below the per-attempt `MAIL_API_TIMEOUT_MS` budget
(default **10000 ms**). It is not a budget for all three attempts and backoffs;
reserve time for in-flight vault work and process cleanup within the stop grace
period.

The writer will not start without mail configuration unless
`INTAKE_NOTIFY=off` is explicitly chosen. That development escape hatch does
not send mail; notification state is recorded as failed with code `disabled`.
It is not suitable when operators depend on completion alerts. Regardless of
UI wording, receipt of a submission does not guarantee notification delivery.
Monitor failures and use `notify-retry` only after resolving their cause.

## Configuration reference

Environment files are not discovered or loaded by intake. `_FILE` variants
are preferred for secrets and take precedence over the corresponding direct
environment value. Key files contain one standard base64-encoded 32-byte key;
a trailing newline is allowed. The fingerprint key requires its own file via
`INTAKE_FINGERPRINT_KEY_FILE`; there is no direct environment-value alternative.
Only writer startup loads it, not web or any CLI command.
Mail token files contain a single nonempty token.
The loader rejects multiline secret values and unsafe secret-file permissions.

All numeric settings below are positive safe integers unless stated otherwise.
Millisecond timer settings (`INTAKE_RATE_WINDOW_MS`, `INTAKE_POLL_MS`,
`INTAKE_IPC_TIMEOUT_MS`, `MAIL_API_TIMEOUT_MS`, both `MAIL_API_RETRY_DELAY_*_MS`
settings, `BW_TIMEOUT_MS`, both `INTAKE_VAULT_RETRY_*_MS` settings,
`INTAKE_UNKNOWN_SETTLE_MS`, and `INTAKE_SHUTDOWN_WAIT_MS`) must also be at most
**2,147,483,647**, avoiding
Node timer clamping. Boolean settings accept `true`, `false`, `1`, or `0`. `INTAKE_NOTIFY` instead
accepts exactly `on` or `off`. Durations use positive whole-number `m`, `h`, or
`d` units. Configuration is read at process startup, not hot-reloaded.

### Shared/public-role configuration

These settings are parsed for every operational CLI command and both application
processes, even if a particular command does not otherwise use the setting.
Provide the HMAC key for those invocations, including `notify-retry`.
`intake --help`, `intake help`, and invocation without arguments print help
without loading configuration (but still refuse root).

| Variable                         | Default                                  | Meaning                                                                                                                                            |
| -------------------------------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INTAKE_DB`                      | `/var/lib/intake/public/tickets.sqlite`  | Shared public SQLite path; parent must exist and support WAL                                                                                       |
| `INTAKE_SOCKET`                  | `/run/intake/writer.sock`                | Shared Unix socket path; parent must already exist                                                                                                 |
| `INTAKE_HMAC_KEY_FILE`           | Required unless direct value is supplied | File containing the base64 32-byte token HMAC key; shared `0640`                                                                                   |
| `INTAKE_HMAC_KEY`                | Unset                                    | Direct base64 HMAC key alternative; never log it                                                                                                   |
| `INTAKE_PUBLIC_URL`              | `https://intake.example.com`             | HTTPS origin, no credentials, query, fragment, or non-root path                                                                                    |
| `INTAKE_MAX_TTL`                 | `7d`                                     | Maximum creation TTL; ticket default is independently `24h`                                                                                        |
| `INTAKE_DEFAULT_NOTIFY_EMAIL`    | Unset                                    | One plain recipient address used when create omits its flag                                                                                        |
| `INTAKE_HOST`                    | `127.0.0.1`                              | Web bind address: only `127.0.0.1` or explicit `0.0.0.0`; Docker sets the latter inside its namespace                                              |
| `PORT`                           | `3000`                                   | Web TCP port, 1–65535                                                                                                                              |
| `INTAKE_HSTS_MAX_AGE`            | `31536000`                               | HSTS max-age in whole seconds; 0 or off omits it; preload is never added                                                                           |
| `INTAKE_HSTS_INCLUDE_SUBDOMAINS` | `true`                                   | Include subdomains of the intake host in HSTS; false keeps max-age only                                                                            |
| `TRUST_PROXY`                    | `false`                                  | Use last X-Forwarded-For element only when no client IP header is configured                                                                       |
| `INTAKE_CLIENT_IP_HEADER`        | Unset (disabled)                         | Single-IP proxy header for rate limits; unset or off disables it, empty is invalid; wins over TRUST_PROXY; exclusive trusted proxy access required |
| `INTAKE_BODY_LIMIT`              | `100000`                                 | Maximum API request body bytes; ciphertext includes JSON/base64 overhead                                                                           |
| `INTAKE_RATE_WINDOW_MS`          | `60000`                                  | Fixed rate-limit window in milliseconds                                                                                                            |
| `INTAKE_RATE_IP_LIMIT`           | `30`                                     | Per-client allowance for open/submit requests; IPv6 uses /64 plus an additional /48 bucket                                                         |
| `INTAKE_RATE_IPV6_48_LIMIT`      | `4 × INTAKE_RATE_IP_LIMIT` (`120`)       | Additional allowance shared across native IPv6 clients in the same /48                                                                             |
| `INTAKE_RATE_TICKET_LIMIT`       | `10`                                     | Failed token verifications per ticket for open/submit; valid tokens bypass this limit, not client limits                                           |
| `INTAKE_RATE_MAX_ENTRIES`        | `10000`                                  | Client and ticket buckets use separate maps, each bounded by this limit (minimum 2); expired-first, then LRU eviction                              |
| `INTAKE_IPC_TIMEOUT_MS`          | `45000`                                  | Unix-socket request timeout in milliseconds for wake-up/manual notification retry                                                                  |
| `INTAKE_POLL_MS`                 | `1000`                                   | Writer's periodic durable queue scan interval in milliseconds                                                                                      |

Rate limiting returns HTTP 429 for a tracked bucket exceeding its fixed-window
allowance, not merely because the table is full. IPv4-mapped IPv6 addresses
(including dotted and hex forms) use the corresponding IPv4 bucket. Native IPv6
addresses are normalized and charged against both a `/64` client bucket and an
additional `/48` bucket. Both allowances must permit the request, and both buckets
are charged even when one rejects it. Rotating interface addresses within a `/64`
or rotating `/64`s within a `/48` therefore does not create independent allowances.
The `/48` allowance defaults to four times the configured per-client allowance.
Per-ticket limits count failed token verifications across client addresses, not
successful opens or submissions. Bad tokens, unknown tickets and unavailable
tickets consume this allowance; malformed envelopes and internal errors do not.
After the allowance is exhausted, wrong or unavailable tokens for that ticket ID
return 429 until the fixed window expires. A valid token for an active, unexpired
ticket bypasses this per-ticket block, so knowing only an ID cannot lock out its
holder. Expired, consumed and revoked tickets do not qualify for the bypass.
Per-client limits still apply to valid tokens and are charged before the body is
read, including malformed or oversized bodies.

Client and ticket buckets are stored in separate bounded maps, each with capacity
`INTAKE_RATE_MAX_ENTRIES`. Capacity must be at least **2** so both native IPv6
prefix buckets can be retained. Client churn cannot evict ticket buckets. Each map
removes expired entries before adding a bucket; adding at capacity evicts the
least recently used remaining entry in that map. Touches, including denied
requests, update LRU order without extending the fixed window. A new client
therefore gets served rather than a capacity-only 429. Eviction resets the evicted
bucket's history, so sufficiently high churn within a map can weaken its limits.
This is a bounded best-effort abuse control, not a guarantee under flooding. The
limiter is process-local and not persistent; new processes start with empty buckets.
Request/header timeouts on the public
HTTP server are fixed at 15/10 seconds, with an 8,192-byte header limit; these
are not configurable environment settings. The Unix-socket API similarly has
fixed 15/10-second request/header timeouts and a 1,024-byte request-body limit.
The submitted plaintext limit is fixed at 65,536 UTF-8 bytes, independently of
the configurable HTTP body limit.

### Private configuration: writer and create/purge CLI only

| Variable                 | Default                                  | Meaning                                                                  |
| ------------------------ | ---------------------------------------- | ------------------------------------------------------------------------ |
| `INTAKE_PRIVATE_DB`      | `/var/lib/intake/private/keys.sqlite`    | Writer-only SQLite path for encrypted PKCS8 keys                         |
| `INTAKE_WRITER_KEY_FILE` | Required unless direct value is supplied | Writer-only `0600` file containing the base64 32-byte AES-GCM master key |
| `INTAKE_WRITER_KEY`      | Unset                                    | Direct base64 master key alternative; never give it to web               |

The CLI's `create` and `purge` paths load this private configuration but do not
require mail or vault environment settings. `list`, `show`, `revoke`, and
`notify-retry` load only the public-role configuration.

### Writer-only notification and vault configuration

| Variable                      | Default                                  | Meaning                                                                                              |
| ----------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `INTAKE_FINGERPRINT_KEY_FILE` | Required, no direct value alternative    | Writer-owned `0600` file containing an independent base64 32-byte HMAC key                           |
| `INTAKE_NOTIFY`               | `on`                                     | Required mail behavior; `off` explicitly disables sending for development                            |
| `INTAKE_SHUTDOWN_WAIT_MS`     | `5000`                                   | In-flight notification shutdown wait; safe integer 0–2147483647 ms; 0 cancels immediately            |
| `MAIL_API_URL`                | Required when notifications are on       | Mail API base URL; HTTPS required except loopback HTTP development                                   |
| `MAIL_API_TOKEN_FILE`         | Required unless direct token is supplied | Writer-only `0600` bearer credential file                                                            |
| `MAIL_API_TOKEN`              | Unset                                    | Direct mail bearer token alternative                                                                 |
| `MAIL_API_MAILBOX`            | Required when notifications are on       | Single sender mailbox address, URL-encoded in the send route                                         |
| `MAIL_API_TIMEOUT_MS`         | `10000`                                  | Per-attempt HTTP timeout in milliseconds                                                             |
| `MAIL_API_RETRY_DELAY_1_MS`   | `1000`                                   | First retry backoff in milliseconds                                                                  |
| `MAIL_API_RETRY_DELAY_2_MS`   | `3000`                                   | Second retry backoff in milliseconds                                                                 |
| `INTAKE_BW_SOCKET`            | `/run/intake-bw/bw.sock`                 | Absolute Unix-socket path, max 103 UTF-8 bytes; writer-owned parent with no group/other access       |
| `INTAKE_BW_URL`               | Unset                                    | Explicit loopback HTTP alternative; conflicts with INTAKE_BW_SOCKET; warns about local-user exposure |
| `BW_ORGANIZATION_ID`          | Required                                 | Organization ID for every new item                                                                   |
| `BW_COLLECTION_ID`            | Required                                 | Dedicated collection ID for every new item                                                           |
| `BW_SYNC_BEFORE_WRITE`        | `true`                                   | Optional sync before creation; unknown-resolution lookup always syncs, even when false               |
| `BW_TIMEOUT_MS`               | `10000`                                  | Per-vault-request timeout in milliseconds; ambiguous item requests become unknown for delayed lookup |
| `INTAKE_VAULT_RETRY_BASE_MS`  | `5000`                                   | Initial persisted backoff for pre-delivery retries and unknown resolution, in milliseconds           |
| `INTAKE_VAULT_RETRY_MAX_MS`   | `300000`                                 | Exponential backoff cap; base <= max <= 2147483647; settle may make the first recovery wait longer   |
| `INTAKE_STUCK_ATTEMPTS`       | `10`                                     | Positive safe integer 1–31; ticket_stuck warning threshold; retries continue                         |
| `INTAKE_UNKNOWN_SETTLE_MS`    | `120000`                                 | Settle after ambiguous POST/commit failure or interrupted processing; positive ms <= 2147483647      |
| `BW_MAX_RESPONSE_BYTES`       | `1048576`                                | Maximum bw serve response bytes (1 MiB), including full collection listings, over either transport   |

`BW_MAX_RESPONSE_BYTES` is a positive safe integer, also passed to writer by
Docker Compose from `.env` or stack environment variables. The adapter counts raw
response bytes as they arrive, including chunked responses, and destroys the
connection on overflow without parsing a partial body. The sanitized error is
`vault_response_too_large`, mapped to `vault_lookup_too_large` for an oversized
recovery listing; no upstream body, listing, or values are logged. This applies
to readiness, sync, collection listing, and item-creation requests. Oversized
initial readiness/sync responses preserve pending work; lookup failures preserve
`unknown` with backoff. An oversized ambiguous item response becomes `unknown`,
retaining envelope/key for later settled lookup rather than immediate replay or
terminal key destruction. An oversized listing never authorizes an item-creation
POST: raise the cap or empty/shrink the dedicated collection by moving **only
items for `done` tickets**, never unresolved ones. Unexpected HTTP protocol
upgrades are rejected as `vault_network` and their sockets are closed; intake
never switches away from the vault's HTTP API. If an item request may have been
delivered, that outcome is ambiguous and follows the same `unknown` recovery.

Both vault IDs remain required even when `INTAKE_NOTIFY=off`. Mail timeouts and
backoffs are parsed only when notifications are enabled. Fixed retry count is
three total attempts, not an additional environment setting. HTTP redirects
must not be used to route credentials or unlocked vault operations elsewhere.

### External CLI/service environment

These are not intake-loader settings, but are used by the example deployments:

| Variable                   | Supplied by                         | Meaning                                                                                     |
| -------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------- |
| `BW_SERVER`                | Compose from `VAULT_URL`            | Vault server origin for the bw bootstrap; never the local management API                    |
| `BW_CLIENTID_FILE`         | bw service only                     | `/run/secrets/bw_client_id`; personal API client ID file                                    |
| `BW_CLIENTSECRET_FILE`     | bw service only                     | `/run/secrets/bw_client_secret`; API client secret file                                     |
| `BW_PASSWORD_FILE`         | bw service only                     | `/run/secrets/bw_master_password`; private password file used to unlock                     |
| `BW_SESSION`               | bw entrypoint, or host `bw.env`     | Unlocked capability only for `bw serve`; never put it in Compose or web/writer environments |
| `BITWARDENCLI_APPDATA_DIR` | bw image, or CLI unit/setup shell   | `/var/lib/intake/bw`; dedicated profile and cached credentials                              |
| `HOME`                     | bw image, or CLI unit/setup shell   | `/var/lib/intake/bw`; never an operator's shared home                                       |
| `NODE_ENV`                 | Images/Compose or application units | `production`; does not change intake's configuration validation                             |

Compose's `*_PATH` variables are host-side secret-file interpolation settings,
not alternatives to the container `*_FILE` settings above. The existing direct
secret-value alternatives remain for host configuration compatibility, but are
not used by this stack.

## Development and validation

```sh
mise install
mise exec -- npm ci
mise exec -- npm run lint
mise exec -- npm run format:check
mise exec -- npm test
# Equivalent aggregate check:
mise exec -- npm run verify
```

Use Node 22.18+ within the 22.x line throughout; do not switch a host-wide runtime just to develop this
project. `npm run format` rewrites supported source/doc files. `npm test` uses
`node:test` through `node --test`. The in-memory `MockVaultAdapter` and local fake
HTTP endpoints are test helpers, not an environment-selectable production vault
mode. The production writer entrypoint constructs `BwServeAdapter`.

With appropriate non-root development accounts, temporary writable directories,
explicitly supplied configuration, and a prepared local CLI API, the entrypoints
are `npm run web` and `npm run writer`. There is no automatic key generation,
account setup, TLS, vault login, or `.env` loading when these commands run.
Never use production credentials for tests. `INTAKE_NOTIFY=off` is only an
explicit development choice, not a way to make production notifications reliable.

Before production, verify permissions under both service identities, concurrent
single-use behavior, queueing while the writer is stopped, restart recovery,
notification failure/retry, actual CLI/API item mapping, and reverse-proxy header
handling. Test the hardening and readiness policy on the target system; passing
unit tests alone does not validate the deployed network/permission boundary.

### Security checks

Run `npm run audit:check` with Node 22 to audit both the root and `docker/bw`
lockfiles without installing their dependencies. The dependency audit
also runs as a step of the `CI` / `test` job on pull requests, pushes to
`main`, weekly, and on manual request; pull requests that only change
Markdown files or `docs/` skip it (and lint, format and tests). Unapproved high/critical advisories, expired exceptions, invalid
allowlists and incomplete audit responses fail the check; lower severities are
reported, and stale exceptions produce warnings.

Grant exceptions only through a reviewed PR to `.audit-allowlist.json`. Each
entry requires the exact GHSA `id`, npm `package`, `target` (`root` or
`docker/bw`), a factual non-placeholder `reason`, and an `expires` date in
`YYYY-MM-DD` format. An exception applies only to that target, advisory and
package; remove it when no longer needed and review it before expiry.

The separate `Security` / `scan` job (`.github/workflows/security.yml`, self-hosted
`s2` runner) runs on every pull request (including documentation-only ones),
on pushes to `main`, on manual request and weekly on Mondays at 04:47 UTC,
normally in under a minute, and
writes its results to the job summary:

- **Semgrep CE 1.182.0** with the public rule packs `p/javascript`,
  `p/nodejsscan`, `p/secrets` and `p/docker`, run locally on the runner (no
  Semgrep login, app token or cloud upload; installed from the hash-pinned
  `.github/semgrep-requirements.txt`, fresh on every run). ERROR findings and
  every scan error (rule timeouts, parse errors; `--strict --timeout 60
--timeout-threshold 3`) fail the job; WARNING and
  INFO findings are only listed. Semgrep's default ignores apply (`.gitignore`d
  paths, `node_modules`, `test/`, build output, minified JS); tests hold
  synthetic credentials and are covered by Gitleaks.
- **Gitleaks 8.30.1** with `.gitleaks.toml` over the full history (pull
  requests: the history of the PR merge commit; otherwise all refs), with fully
  redacted output.

Run them locally (e.g. `uv tool install semgrep==1.182.0`):

```sh
gitleaks git --redact=100 --config .gitleaks.toml --log-opts="--all --diff-merges=first-parent" .
semgrep scan --metrics off --config p/javascript --config p/nodejsscan \
  --config p/secrets --config p/docker --strict --timeout 60 --severity ERROR --error .
```

For a reviewed Semgrep false positive, add `// nosemgrep: <rule-id> -- <reason>`
on the line above the finding. The Docker image build runs on pushes to `main`
and on pull requests that change the Dockerfile, `docker/` or a lockfile. Any
fixture or documentation exclusion must be narrow, commented and reviewed; never
allowlist real credentials. Dependabot checks GitHub Actions and both npm trees
weekly.

## License

MIT; see [LICENSE](LICENSE). The license file is unchanged.
