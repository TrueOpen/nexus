# nexus

The off-chain coordinator process co-located with the local `node` on a TrueOpen Builder machine.
Integration notes live in `docs/`; the protocol wire (proto, domain registry and golden vectors) is published in the public
[TrueOpen/wire](https://github.com/TrueOpen/wire) repository.

> Current state: a **runnable skeleton**. Module boundaries, lifecycle and the order ingress are in place;
> chaincli is wired to the local node for query / broadcast / subscription transport. Order dispatch to
> Cortex nodes is not implemented yet: a new order is refused with `Unimplemented`
> (`NEXUS_INGRESS_DISPATCH_NOT_IMPLEMENTED`), and the Cortex dispatch stream is not served (Builder
> messages to Cortex are signed and then dropped).

## Commands (cobra)

```bash
nexus start      # start the service
nexus version    # version
nexus keys create-keystore  # convert a hex private key into an encrypted keystore
nexus builder register       # ensure the Builder record and descriptor on the Hub match local config
nexus drain begin|end|status # optionally stop new work on the running Builder (see below)
nexus status     # readiness, diagnostics, drain and metrics as the running daemon last wrote them
nexus --help     # help
```

### Service key rotation

A rotation registered in epoch E becomes current at the start of epoch E+2; nothing postpones it.
The chain keeps the replaced key as the one previous generation: it still proves the tickets,
roots, records and Worker answers of orders whose `earliest_submit_height` is below the cutover,
and the Builder messages of tasks recorded before it. No drain is needed:

1. Put the new service key next to the current one: `identity.next_service_keystore_file` and
   `identity.next_service_keystore_password_file` (needs a dedicated `service_keystore_file`).
   Restart once so the daemon holds both keys, then submit the rotation with the operator key.
2. While the rotation is pending the Builder takes no new order at all, so its current key signs no
   material of an order at or above the effective height. OpenTask answers every order it does not
   already hold (the first order of a session, the next sequence of a session bound to it, a resend
   after a failed attempt, a takeover request) with `NEXUS_INGRESS_BUILDER_KEY_ROTATING`
   (Unavailable), checked before any other precheck, with the effective height as
   `service_key_rotation_effective_height` and at the end of the message; the SDK treats it like
   `NEXUS_INGRESS_NO_CAPACITY` and takes the session over to another Builder (skipping pending
   Builders, and waiting for the earliest activation when every candidate is pending), so each
   session active here moves once. An exact resend of an order it holds is still answered with its state,
   and everything already under way goes on under the current key: tickets out are accepted, inputs
   delivered, records sent, outputs relayed, claims rebutted and challenges answered. A held
   takeover whose entry no transaction carries yet ends with its input dropped (task event
   `NO_CAPACITY`, the closed event set having no rotation code; a resend is answered
   `NEXUS_INGRESS_BUILDER_KEY_ROTATING`), on this Builder's own `SERVICE_KEY_ROTATION_REGISTERED`
   event or when it is judged again after a restart; one whose entry went out or that the chain
   registered goes on. Handraise roots are still signed with the current key, each with a
   `root_height` below the effective height (the retired key still proves it after the cutover): an
   order already taken that needs another round (a binding change voided its ticket) binds the
   latest root as usual. Should the local height reach the effective height before the chain's
   binding shows the cutover, no root is signed until it does (logged once as `handraise roots wait
   until the chain shows the Builder service key cutover`). The pending state is read from the
   chain's binding on every order, so a restart in the window refuses as well. A Cortex that
   registered a rotation keeps its stream for its tasks under way, but its standing handraise is
   not admitted in the roots (`SERVICE_KEY_ROTATION_PENDING`) until its rotation activates. `nexus
   status` warns when the registered key is not held locally. Rotate one BuilderSet member at a
   time, preferably off peak; `nexus drain begin` before the registration stops new orders earlier
   still.
3. At the effective height the daemon signs with the new key without a restart: tickets, records,
   roots (signed again), result headers, input chunks, record notices and record transactions
   from the new service account. Cortex streams stay up. Keep the old key configured (as either
   keystore) while tasks recorded before the cutover are still open: their Builder messages keep
   its nonce. Since either slot may hold the retired key, the daemon signs nothing until it has
   read the chain's binding: it reads it at startup and, if the chain does not answer, keeps
   reading it in the background.

An emergency revocation (`MsgRevokeServiceKey`) is different: the revoked key stops at once and no
replacement comes with it. From this Builder's own `SERVICE_KEY_REVOKED` event (or the next read of
its binding, at startup too) until a replacement is current, the daemon signs nothing new: no
tickets, roots, records, result headers, input chunks, record notices, group sync requests,
Builder messages to Cortex or transactions from the service account. What it signed before is
never signed again: stored result headers are still served as first signed, unacknowledged stream
messages keep their bytes for when Cortex nodes, which close their streams to a revoked Builder,
bind again, and sync items wait for the first sync request signed after the replacement. While
revoked:

- the log says `service key revoked: nothing is signed and no order is dispatched until a
  replacement key is current` (error) and `handraise roots paused while this Builder's service key
  is revoked`; `/readyz` turns 503 with `builder_key` failing as `this Builder's current service
  key is revoked (nonce N)`, followed by `no replacement is registered` or `replacement nonce M is
  current from height H`; `nexus status` shows the `service_key` diagnostic as
  `inactive BUILDER service key (REVOKED)`;
- OpenTask answers `NEXUS_INGRESS_DISPATCH_NOT_READY` with `dispatch_available_height` set to the
  replacement's effective height once one is registered, and `NEXUS_INGRESS_NO_CAPACITY` (as during
  a drain) before that; no takeover is admitted (`NEXUS_INGRESS_NO_CAPACITY`);
- an order still dispatching fails as no capacity instead of getting another ticket, and an
  accept of a ticket signed before the revocation is answered `DISPATCH_TICKET_CLOSED`: the
  attempt is `VOIDED` with the accept kept, so the GPU is left to a compensation claim;
- held takeovers whose entry has not gone out end as `NO_CAPACITY`; those whose entry went out
  finish on chain;
- the service account signs no transaction, so this daemon rebuts no compensation claim and
  answers no dispatch challenge (logged once as `rebuttals and challenge answers held`, counted in
  the `answers_held_revoked` diagnostic). They are tried again every block and go out once a
  replacement key is current. Until then the other members of the order's Task Builders group
  answer in the second half of each window from the copy of the evidence synced to them; no new
  evidence is synced while the key is revoked (sync requests need the current key), so a claim or
  challenge whose evidence did not reach a member before the revocation, and whose window closes
  before the replacement is current, is paid out or penalized even though this daemon holds the
  evidence against it.

That last point is why a replacement should be registered at once, as in step 1; it becomes
current at the start of epoch E+2 like any rotation. At its effective height the daemon finds it
current and resumes signing, dispatch and the held answers by itself, without a restart.

`nexus drain begin` remains for an operator who wants a quiet Builder: it takes no new order,
issues no ticket and admits no takeover (OpenTask answers `NEXUS_INGRESS_NO_CAPACITY`); in-flight
orders are accepted, recorded or fail as usual, and the group sync finishes. A held takeover whose
entry has not gone out is ended as `NO_CAPACITY` at once; one whose entry went out takes effect.
`/readyz` turns 503. `nexus drain status` shows `DRAINING`, `DRAINED` or `ROTATION_PENDING`, what
remains, and ends by itself once the chain shows a new key current that the daemon holds
(`nexus drain end` ends it at any time).

Messages the Builder signed before the cutover (tickets, records, roots, result headers, input
chunks and record notices) name the key generation that signed them and are never signed again:
stored result headers, unacknowledged stream messages and group sync items go out byte for byte
as first signed, and still prove orders below the cutover under the retired key. New messages are
signed with the new key; only the group sync request is signed again, with the current key, at
every send. nexus sends no revoke yet.

A Cortex stream is bound by the Cortex's current ACTIVE key and checked once, so the daemon ends
it as soon as it sees that key rotated out or revoked (from the chain's key events, and on each
keepalive tick in case an event was missed); the Cortex binds again under its new key.

The commands talk to the daemon through `<data_dir>/ops` (a request file taken on the daemon's
next tick, and `status.json` it rewrites every two seconds); no port is opened. The drain state
is stored, so it survives a restart, and a request left while the daemon is down is applied at
its next start.

## Running

`github.com/TrueOpen/wire` is a private module, so set `GOPRIVATE=github.com/TrueOpen/*` and
make sure git can reach GitHub with your credentials before the first build.

```bash
make run                     # = go run ./cmd/nexus start
# or
make build && ./bin/nexus start
```

Connect serves gRPC, gRPC-Web, HTTP/JSON and `/healthz` on a **single port `:8080`**. To verify:

```bash
# Health check (plain HTTP, hit it with curl)
curl localhost:8080/healthz                       # {"status":"ok"}
curl localhost:8080/readyz                        # 200 {"ready":true} or 503 naming the failed checks
curl localhost:8080/v1/dispatch/stats             # public dispatch statistics (RTT admission threshold, timeout/reject rates, skips)
# The statistics are this Builder's local observations since its start, per Cortex operator; they
# are not chain facts and are no basis for an SLA. They carry no per-order or per-model data.

# Option 1: HTTP/JSON (Connect protocol, no grpcurl needed). Orders go through the OpenTask
# client stream, which the SDK builds and signs; a unary JSON call shows the endpoint is up.
# Hash32 strings on the IngressAPI are 0x followed by 64 lowercase hex characters:
curl -X POST localhost:8080/nexus.v1.IngressAPI/GetTaskStatus \
  -H 'Content-Type: application/json' -d '{"sessionId":"0x<session_id>","taskId":"0x<task_id>"}'

# Option 2: gRPC (reflection is enabled, so grpcurl needs no proto files)
grpcurl -plaintext localhost:8080 list
grpcurl -plaintext -d '{"sessionId":"0x<session_id>","taskId":"0x<task_id>"}' \
  localhost:8080 nexus.v1.IngressAPI/GetTaskStatus

# When api-key is enabled, pass the header (same name for curl and grpcurl):
curl    -H 'x-api-key: <key>' ...
grpcurl -H 'x-api-key: <key>' ...
```

`Ctrl+C` triggers a graceful shutdown.

## Proto / code generation

```bash
make install-tools   # install protoc-gen-go / protoc-gen-go-grpc / grpcurl (once)
make proto           # buf generate → gen/
make proto-lint
```
The Nexus API proto lives in `proto/nexus/v1/`; the Node public wire mirror lives in
`proto/task/v1/`, `proto/hub/v1/` and `proto/shared/v1/`. Generated code lives in
`gen/` (committed, so builds do not need to run buf first) and must not be edited by hand.

`nexus.v1` is also a frozen package of the TrueOpen/wire release (`release/packages.json`), so
`proto/nexus/v1/` must stay field-for-field identical to the wire copy; `tools/mirror_wire.py`
mirrors it like the other packages. `internal/ingress/wire_descriptor_test.go` pins its descriptor
fingerprint to the wire definition pinned in `go.mod`; `internal/chaincli/node_descriptor_test.go`
does the same for the mirrored packages. A wire bump updates the proto, `gen/` and both pinned
values together.

### Consuming the contract (`gen/trueopen` standalone module)

`gen/trueopen` is a standalone Go module (`github.com/TrueOpen/nexus/gen/trueopen`). External Go consumers
(such as Cortex) depend on it to get the IngressAPI Connect client without pulling in Nexus server dependencies.
Usage and access requirements are in [gen/trueopen/README.md](gen/trueopen/README.md).

## Compatibility

nexus is built against TrueOpen/wire commit `55d875b` (Go pseudo-version
`v0.5.2-0.20261029040229-55d875b768e5`, see `go.mod`). TrueOpen/node must pin the same wire
commit in `wire/pin.json`. Node, Nexus, the user SDK and Cortex share this one wire contract and must be deployed
from matching releases; there is no compatibility layer for other signing domains, task IDs or event
ABIs. The full wire, signatures, on-chain / local field boundaries and operating steps are in
[`docs/node-message-integration.md`](docs/node-message-integration.md).

### Local state across upgrades

The kv store records the version of the local state layout. A newer nexus migrates older state in
place at startup, one step at a time, so upgrading nexus or upgrading the chain in place keeps the
local state. An older nexus refuses to start on state written by a newer one. Before upgrading to a nexus
that raises the local state version, back up `data_dir`: going back to the older nexus is only
possible by restoring that backup. Only a reset of the chain (a different block
at height 1) moves the local state aside.

## Interface alignment

`IngressAPI` serves the SDK (User) methods and the Worker / Verifier-side methods; they follow the
public TrueOpen/wire definitions.

Open items:

- `OpenTask` refuses every new order with `Unimplemented` (`NEXUS_INGRESS_DISPATCH_NOT_IMPLEMENTED`)
  before storing its input: dispatching orders to Cortex nodes is not implemented yet. An exact retry
  of a task this Builder already tracks or finished still succeeds.
- `DispatchStream`, `ResumeOutput` and `GetDispatchRoster` return `Unimplemented`.
- `SubscribeOutput` and `AckOutput` serve only the streaming OUTPUT data plane
  (`task_data.output_stream`); without it they return `Unimplemented`.
- Replacing a pending order is not supported yet. An `OpenTask` for a `(session_id, task_id)` this
  Builder already tracks with a different `task_hash` returns `FailedPrecondition`
  (`NEXUS_INGRESS_ORDER_REPLACEMENT_UNSUPPORTED`), and one for a task that already finished with a
  different `task_hash` returns `FailedPrecondition` (`NEXUS_INGRESS_TASK_TERMINAL`). The tracked
  version is kept and the refused input is not kept. An exact retry of the tracked version still
  succeeds. The caller must not retry the refused version, here or on another Builder.
- `OpenTask` refuses an order whose `builder_set_id` / `builder_set_hash` is not the current
  BuilderSet snapshot with `FailedPrecondition` (`NEXUS_INGRESS_BUILDER_SET_STALE`) before storing
  its input; the SDK re-signs the same sequence against the current snapshot (no takeover). Before
  calling an order stale this Builder reads the BuilderSet from the chain again (within 2s), in
  case its own view is the one behind. Such a read starts at most once a second and no request waits
  for another's: while one runs, within a second of the last, or when it fails, the answer is
  `Unavailable` (`NEXUS_INGRESS_DISPATCH_UNAVAILABLE`), as is every new order until a current
  snapshot is known.
- `OpenTask` refuses an order whose epoch cannot dispatch yet (epoch 0, an epoch start beacon not
  committed or verified yet, or an epoch candidate pool snapshot not effective yet) with
  `Unavailable` (`NEXUS_INGRESS_DISPATCH_NOT_READY`) before storing its input; the SDK waits and
  retries the same Builder. When the height from which dispatch is possible is known it is the
  `OpenTaskResponse` detail's `dispatch_available_height`, and the message ends with
  `dispatchable_height=<n>`.
- `NEXUS_INGRESS_BUILDER_KEY_ROTATING` (every new order refused while this Builder's key rotation
  is pending, see Service key rotation) is `Unavailable` and carries the activation height as the
  `OpenTaskResponse` detail's `service_key_rotation_effective_height`; the message ends with
  `effective_height=<n>`.
- `OpenTask` refuses an order whose `order_expire_height` the current height has passed, the same
  boundary the chain applies when it admits a new task: `FailedPrecondition`
  (`NEXUS_INGRESS_ORDER_EXPIRED`), before the request nonce is used and before anything is stored.
- `PrepareChallengeResponse.challenge_close_height` is a block height, while the SDK-facing name of the
  field is `challenge_close` without a fixed unit; the rename waits for that decision.
- Session lifecycle sweeps (`DEADLINE_SWEPT` with `deadline_kind` `SESSION_LIFECYCLE`, i.e. ACTIVE ->
  IDLE -> CLOSED on chain) are skipped on the task event stream; the coordinator does not yet
  react to a session closing (rejecting new orders, releasing per-session state).
- Encryption is not active: orders, receipts, results and stream headers are admitted only in their
  plaintext form (every key commitment 32 zero bytes, no recipient key).
- `FinalizeTaskResult` finalizes one Worker bundle per call. Both calls of a result carry the same
  receipt; the first freezes the OUTPUT and both return the same OUTPUT confirmation plus the
  bundle's. The result is data-ready only once the OUTPUT and both bundles are READY.
- The streamed upload's request body still uses the upload body domain projected onto a zero
  content hash, since wire has not registered a body domain for it; it moves to one once wire does.
- `OutputStreamHeaderV2` is verified and kept but not replayed: `SubscribeOutputResponse` has no
  header frame.

## Configuration (environment variables)

The recommended way is to copy the example YAML and start. `nexus start` automatically loads
`./nexus.yaml` from the current directory; another file can be given with `--config`:

```bash
cp nexus.example.yaml nexus.yaml
./bin/nexus start

# or explicitly; startup fails if the explicit file does not exist
./bin/nexus start --config /etc/nexus/nexus.yaml
```

Configuration precedence: built-in defaults `<` YAML `<` environment variables `<` CLI flags. YAML
uses strict field validation; unknown fields or type errors block startup. Relative file paths in YAML
are resolved relative to the YAML file's directory; relative paths in environment variables are still resolved relative to the current working directory.
`nexus version` and `nexus --version` do not read the config file.

See `nexus.example.yaml` for the full field list. The real `nexus.yaml` is in `.gitignore`;
do not store real private keys or passwords directly in the config file, prefer `private_key_file` and password files.

Environment variables can still override YAML or keep an existing deployment style:

| Variable | Default | Description |
|---|---|---|
| `NEXUS_INGRESS_ADDR` | `:8080` | Public listen address (Connect: gRPC + gRPC-Web + HTTP/JSON + /healthz) |
| `NEXUS_LOG_LEVEL` | `info` | `debug/info/warn/error` (overridden by flag `--log-level`) |
| `NEXUS_LOG_FORMAT` | `text` | `text/json` (overridden by flag `--log-format`) |
| `NEXUS_LOG_FILE` | (empty) | Log file path; non-empty = stdout + file, rotated per the policy below (overridden by flag `--log-file`) |
| `NEXUS_LOG_MAX_SIZE_MB` | `100` | Per-file size cap; rotate when exceeded |
| `NEXUS_LOG_MAX_BACKUPS` | `7` | Number of old files to keep |
| `NEXUS_LOG_MAX_AGE_DAYS` | `28` | Days to keep old files |
| `NEXUS_LOG_COMPRESS` | `true` | gzip rotated files |
| `NEXUS_DATA_DIR` | `./data` | Local data directory (used once pebble is wired in) |
| `NEXUS_INGRESS_MAX_SESSION_GRANT_BLOCKS` | `17280` | Longest session grant a user may sign, in blocks past the current height; must be the same on every Builder |
| `NEXUS_INGRESS_SESSION_KEY_CACHE_TTL_BLOCKS` | `5` | Blocks the chain state of a session's registered key is reused for (1..10) |
| `NEXUS_INGRESS_SESSION_KEY_LOOKUPS_PER_SECOND` | `20` | Chain reads of session state allowed per second on cache misses |
| `NEXUS_INGRESS_OUTPUT_REPLICA_WAIT` | `2s` | Longest wait of a Task Builders group member for its replica of a recorded task before `NEXUS_OUTPUT_REPLICA_NOT_READY` (below 10s) |
| `NEXUS_API_KEYS` | (empty) | Comma-separated list of valid api-keys; empty = no check |
| `NEXUS_IP_WHITELIST` | (empty) | Comma-separated allowed IPs/CIDRs; empty = unrestricted |
| `NEXUS_PAYLOAD_MAX_BYTES` | `16777216` | Max bytes of a single encrypted task input; also derives the Ingress message/body limit; inputs are retained until the on-chain deadline or task terminal state |
| `NEXUS_OUTPUT_REQUIRE_PLAINTEXT` | `false` | Whether outputdelivery requires plaintext; after the Cortex contract removed the Worker-side inline plaintext entry this switch has no production caller |
| `NEXUS_OUTPUT_MAX_BYTES` | `1048576` | Max bytes of a single UTF-8 plaintext output |
| `NEXUS_OUTPUT_PLAINTEXT_TTL` | `4h` | Hard retention cap for un-ACKed plaintext; on expiry it is forced unreadable and cleaned up |
| `NEXUS_OUTPUT_TOMBSTONE_TTL` | `24h` | Minimum retention for ACKed / expired / no-result tombstones |
| `NEXUS_OUTPUT_SWEEP_INTERVAL` | `1m` | Sweep interval for plaintext expiry and tombstone cleanup |
| `NEXUS_CHAIN_GRPC` | `localhost:9090` | Task node gRPC; used for queries, tx broadcast, TaskEventService subscription and height polling |
| `NEXUS_CHAIN_ID` | `trueopen-localnet-1` | Chain ID |
| `NEXUS_HUB_ENABLED` | `false` | Enable a standalone Hub; when enabled, Builder registration, stake and unbond go only to the Hub |
| `NEXUS_HUB_GRPC` | (empty) | Hub node gRPC; required when `NEXUS_HUB_ENABLED=true`, also used for protocol event subscription |
| `NEXUS_HUB_CHAIN_ID` | (empty) | Hub chain ID; required when the Hub is enabled |
| `NEXUS_HUB_TX_GAS_LIMIT` | `200000` | Hub tx gas limit |
| `NEXUS_HUB_TX_FEE_DENOM` | (empty) | Hub tx fee denom |
| `NEXUS_HUB_TX_FEE_AMOUNT` | (empty) | Hub tx fee amount |
| `NEXUS_BUILDER_ADDRESS` | (empty) | This node's on-chain builder address (bech32); empty = identity not configured (used for the active-set self-check and per-order rank) |
| `NEXUS_KEYSTORE_FILE` | (empty) | Encrypted armor keystore produced by Cosmos SDK `keys export`; recommended production signing entry |
| `NEXUS_KEYSTORE_PASSWORD_FILE` | (empty) | Keystore passphrase file, recommended for production |
| `NEXUS_KEYSTORE_PASSWORD` | (empty) | Keystore passphrase, for dev/test |
| `NEXUS_PRIVATE_KEY_FILE` | (empty) | Cosmos armor private key file, or a hex file exported with `--unsafe --unarmored-hex`; used when no keystore is configured |
| `NEXUS_PRIVATE_KEY` | (empty) | Cosmos armor private key content, or hex content exported with `--unsafe --unarmored-hex` |
| `NEXUS_PRIVATE_KEY_HEX` | (empty) | Legacy compatibility: 32-byte secp256k1 hex; for dev/test |
| `NEXUS_PUBLIC_ENDPOINT` | (empty) | Public absolute `http/https` endpoint of nexus; written to the Builder Registry as SHA-256 |
| `NEXUS_BUILDER_BOND_DENOM` | (empty) | Legacy compatibility; the current node's `MsgBondBuilder` does not accept a denom |
| `NEXUS_BUILDER_BOND_AMOUNT` | (empty) | Initial Builder bond amount, sent as uint64 to `MsgBondBuilder.amount` |
| `NEXUS_BUILDER_MONIKER` | (empty) | Forms the canonical metadata together with the P2P hint, written to the Registry as SHA-256 |
| `NEXUS_BUILDER_P2P_HINT` | (empty) | P2P access hint in the Builder metadata |

## Output delivery

OUTPUT is delivered over the streaming data plane (`task_data.output_stream`, enabled by default):
the Worker uploads Worker-signed frames with `UploadTaskOutputStream`, the user SDK receives them with
`SubscribeOutput` (stored frames first, then live ones) and verifies each frame signature and the
output root itself, and `AckOutput` only records delivery progress. The persisted OUTPUT object is
also available through `GetTaskDataMetadata` + `FetchTaskData(OUTPUT)`.

With `task_data.output_stream.enabled=false`, `SubscribeOutput` / `AckOutput` fall back to the legacy
whole-plaintext path described below. Nothing writes plaintext into that path today, so a
subscription returns `unavailable`.

Legacy plaintext retrieval flow:

1. Sign the `SDKRequestEnvelopeV2` for `SubscribeOutput` with the original ordering address (or a
   session key it granted). The method is `SubscribeOutput`, the endpoint is
   `/nexus.v1.IngressAPI/SubscribeOutput`, and the body digest uses the
   `TRUEOPEN_SDK_BODY_SUBSCRIBE_OUTPUT_V1` domain.
2. Call the server-streaming `SubscribeOutput`. The connection waits while the output has not arrived; once it arrives it returns
   exactly one response containing `output_id/output_text/output_hash/created_at/expires_at` and ends.
3. After the SDK has durably saved the plaintext, sign and call `AckOutput`. The method is `AckOutput`, the endpoint is
   `/nexus.v1.IngressAPI/AckOutput`, and the body digest uses the
   `TRUEOPEN_SDK_BODY_ACK_OUTPUT_V1` domain.
4. Only a successful ACK means consumption is complete. On disconnect or missing ACK, the SDK can re-subscribe and receive the same
   `output_id`; ACK is idempotent within the tombstone retention period, and repeated calls return `already_acked=true`.

These two RPCs always enforce a valid SDK envelope; even `require_sdk_envelope=false` cannot bypass it.
Nexus only allows the original ordering address to subscribe and ACK. Plaintext is written to local Pebble and is currently **not encrypted at rest**;
after the first ACK it is immediately removed from the read path and physical deletion is attempted, and un-ACKed data is
force-cleaned after the default 4-hour hard TTL. A tombstone is kept for at least 24 hours by default to block replay recovery; it contains no plaintext.
Production deployments should restrict data directory permissions, disk backup scope and operator access to the node.

## Task Builders group sync

Every order this Builder dispatches is synced to the other Builders of the order's Task Builders
group over `BuilderSyncService` on the ingress port (batches signed with the Builder service key, no
API key; limited per source address by `ingress.builder_sync_requests_per_second` and
`ingress.builder_sync_burst`, defaults 1000 and 2000). The dispatching side keeps an outbox per order
and deletes the items every member applied.

A member serves `SubscribeOutput` / `ResumeOutput` of an order (from its replica) once the chain
has recorded the order with the member in its Task Builders group, which it confirms with the
chain's Task Builders query (a recorded group is cached; "not recorded" for one second). Before
that the answer is `FailedPrecondition` (`NEXUS_INGRESS_SESSION_UNBOUND`). After it, a replica that
has not caught up yet is waited for at most `ingress.output_replica_wait` (default 2s, must be
below 10s; and at most half the time left to the request's own deadline); then the answer is the
retryable `Unavailable` (`NEXUS_OUTPUT_REPLICA_NOT_READY`), and the SDK retries or falls back to
`FetchTaskData(OUTPUT)`.

A member that later reports fewer items than were deleted has lost its data directory. It is logged
once as an error ("group member holds fewer of an order's sync items ...") and counted as an alarm,
and it cannot stand in for this Builder on that order; the other members still can. Nothing else is
sent to it on that order except a probe every 10 minutes with the items still held. To clear the
mark, restore that member's data directory from a backup taken after it held the deleted items: the
next probe finds it caught up, logs "the mark is cleared" and syncing resumes. Without a backup no
action is needed; the mark goes with the order's sync stream when its retention ends.

## User request signing

User requests carry an `SDKRequestEnvelopeV2`: a 65-byte `R || S || V` signature (`V` 27 or 28,
low-S) over the EIP-712 `SDKRequest` typed data in the domain `"TrueOpen SDK Request"` version `"1"`,
with `chainId` = the envelope's `signature_chain_id`. The signer chooses that value (a browser
wallet uses its active network, so the user never switches networks) and it must be in
`1..MaxInt64`; it isolates nothing, since the typed `chainId` string is always this chain's
`chain_id`, and it enters no replay key. Nexus recovers the signer
and requires it to match the account's public key stored on chain; an account with no stored key is
rejected. The body digest of each method uses its own `TRUEOPEN_SDK_BODY_*_V1` domain.

- `OpenTask` is signed by the order's user wallet, by a session key under a grant whose user is
  the `SignedOrderV2` user (otherwise `SDK_AUTH_SESSION_GRANT_INVALID`), or by the session's
  registered key (below). The order itself is signed by the wallet or by the registered key; a
  grant never authorizes an order. The header's own `signature` / `signature_scheme` must be empty,
  and `order_envelope` must be a `SignedOrderV2`.
- A user can sign a `SessionGrantV1` once to let a session key sign `OpenTask`, `SubscribeOutput`, `AckOutput`,
  `GetTaskEvents`, `PrepareChallenge`, and `GetTaskDataMetadata` / `FetchTaskData` of an OUTPUT
  object. The grant expires at a chain height no more than `ingress.max_session_grant_blocks` past
  the current height.
- USER task data requests use the EIP-712 `TaskDataRequest` domain version `"2"`; version 1
  signatures are rejected.
- Checks run in wire order and stop at the first failure: format (`NEXUS_INGRESS_MALFORMED`),
  session method set, grant, signature over the digest rebuilt with this chain's `chain_id` and
  the carried `signature_chain_id` (`SDK_AUTH_INVALID_SIGNATURE` / `DATA_ACCESS_INVALID_SIGNATURE`), then expiry and
  replay. An OpenTask expiry is a chain height within `task_data.request_ttl_blocks` (default 20);
  a Task data request expiry lies within the Hub parameter
  `service.max_service_material_expiry_blocks`, read at startup and re-read every 10 minutes.
- One user account may make at most `task_data.user_requests_per_minute` Task data requests per
  minute (default 600); over the cap the request is refused with `NEXUS_DATA_CAPACITY` before its
  nonce is stored. An object deleted when its retention ran out is `DATA_EXPIRED`. Its tombstone,
  which also refuses a re-upload of the same key, is kept for `task_data.tombstone_retention_blocks`
  (default 120960) after the later of its deletion height and its retention height; after that the
  key answers `NEXUS_DATA_NOT_FOUND`. 0 keeps tombstones forever.
- INPUT is served only in the version the chain accepted: a fetch or metadata request must name
  the task's `accepted_task_hash` (and its `accepted_input_hash` once the chain reports it);
  another version is refused with `DATA_ACCESS_DENIED`. A Builder whose own order was another
  version deletes that input and never reports itself data-ready for verification of the task.

This is not compatible with SDK releases built for wire v0.3.x; nexus and the SDK must be upgraded
together.

### Registered session keys

A session owner may register one signing key on the session's on-chain `StreamState`
(`MsgCreateSession` or `MsgUpdateSessionKey`, both signed by the wallet). That key may then sign,
without a `SessionGrantV1`:

- the session's closed set of requests above. A request without a grant that recovers to an address
  other than `signer_address` / `requester_address` is checked in order: the session (the
  envelope's `session_id`; for Task data requests the session of this Builder's local record of the
  Task, and no local record is a rejection) exists, is not CLOSED, is owned by the signer and has the
  recovered address as its current key, else `SDK_AUTH_INVALID_SIGNATURE` /
  `DATA_ACCESS_INVALID_SIGNATURE`; the key has not expired, else `SDK_AUTH_SESSION_GRANT_EXPIRED` /
  `DATA_ACCESS_SESSION_GRANT_EXPIRED`; the method is in the session set, else
  `SDK_AUTH_SESSION_METHOD_NOT_ALLOWED` / `DATA_ACCESS_SESSION_METHOD_NOT_ALLOWED`.
- `SignedOrderV2` orders of the session. Before the request nonce is used or the input stored,
  OpenTask recovers the order signer (the order domain's `feeDenom` is the Hub `phase0.business_denom`,
  read at startup from the Hub endpoint, which must equal the business_denom the Task chain's Keeper
  verifies with; changing it needs a restart). A wallet order goes on as before. Any other signer
  must be the current key, registered at or before the order's signed `session_anchor_height`
  (else `SDK_AUTH_INVALID_SIGNATURE`), not expired (else `SDK_AUTH_SESSION_GRANT_EXPIRED`), and the
  committed `session_key_spent` plus the order's `max_fee` must stay within a nonzero
  `session_key_spend_cap` and within the chain's uint64 counter (else
  `SDK_AUTH_SESSION_KEY_SPEND_CAP_EXCEEDED`). In-flight orders are not counted. A wallet order whose
  signature does not recover to its user now fails here with `SDK_AUTH_INVALID_SIGNATURE` instead of
  on chain. The Keeper remains the final authority: if it refuses the order's dispatch entry the task
  ends with `RECORD_REJECTED` and the client re-signs the same sequence.

Session state is cached by session for `ingress.session_key_cache_ttl_blocks` blocks (1..10,
default 5) past the height it was read at; "no such session" and "no key" are cached too. At most
`ingress.session_key_lookups_per_second` (default 20) cache misses read the chain; more are answered
`Unavailable` and retried by the client. A registered-key request or order whose current height or
session state cannot be read from the chain is refused with `SDK_AUTH_INVALID_SIGNATURE`
(`DATA_ACCESS_INVALID_SIGNATURE` for Task data requests): without chain state nothing vouches for
the key. The checks use the current height the request path reads
for session grant windows; an OpenTask with a registered-key order reads it once for both the
envelope and the order.

Known limits:

- The chain delivers `session_key_updated` (event 106) only on the per-session task event stream,
  and Nexus subscribes only to sessions it tracks tasks for. For those sessions an update or a
  stream reconnect drops the cached state, and nothing is cached while the stream is down. For other
  sessions the block expiry is the only bound: there it covers the OpenTask precheck and the cached
  "no key" answers; other requests for untracked sessions already fail for lack of a local task.
  After a key is cleared or rotated, this Builder may accept requests signed by the old key for up
  to the cache expiry; orders are still decided by the Keeper.
- Session state queries and the task event streams must come from the same node. A query answered
  by a node behind the block of a key update may cache the old state after the update event was
  seen, and then only the block expiry bounds it.
- Every OpenTask whose order signature recovers to an address other than its user costs a height
  read and a session lookup before the request envelope is checked. Misses are bounded by
  `ingress.session_key_lookups_per_second`; when garbage orders spend that budget, genuine
  registered-key requests get `Unavailable` until it refills.
- Upgrade order: Nexus must run this mirror before the Node emits event 106. An older Nexus treats
  an unknown event without `task_id` as malformed and its stream for that session stalls on the
  event; this version skips such events with a warning.

## Builder registration

In Hub + Task Chain mode, `chain` always means the task chain; the Coordinator's task queries, transactions and events go through that chain. With `hub.enabled=true`, the Builder's Node Registry, stake and unbond use only `hub`. The Task Chain does not accept Builder registration transactions; identity and stake state are obtained later via Hub snapshots. Incomplete Hub configuration blocks startup and does not silently fall back to the Task Chain. Without the Hub, single-chain compatibility mode is retained and an explicit warning is printed.

The Node must enable TaskEventService. Task node setting:

```text
NODED_TASK_EVENT_GRPC_ENABLED=true
```

In single-chain compatibility mode (`hub.enabled=false`) the same node provides protocol events, so that node must also set:

```text
NODED_TASK_EVENT_GRPC_PROTOCOL_EVENTS_ENABLED=true
```

A standalone Hub node must enable both the base service and protocol events:

```text
NODED_TASK_EVENT_GRPC_ENABLED=true
NODED_TASK_EVENT_GRPC_PROTOCOL_EVENTS_ENABLED=true
```

With a signer configured, `nexus builder register` submits to the Builder registry chain (`nexus start` only checks, never submits):

```text
MsgRegisterBuilder{service_pubkey, service_key_proof, descriptor}      # when not yet registered
MsgUpdateServiceDescriptor{expected_descriptor_version, descriptor}    # when the on-chain descriptor differs from local config
```

Phase 0 has no BuilderBond (fixed at zero; no bonded stake record is created); admission is fixed by governance/genesis. Observation
is partitioned by `authority_chain_id + builder`, so switching Hubs never reuses results from the old chain.

Deterministic rejections such as configuration errors, identity mismatch or insufficient balance block startup. When the node is temporarily unreachable, the check in `nexus start`
is deferred and startup continues (when TLS is off); with TLS on, startup is refused.

`NEXUS_KEYSTORE_FILE` takes the output file of the chain CLI's `keys export`, which looks like:

```text
-----BEGIN TENDERMINT PRIVATE KEY-----
kdf: argon2
salt: ...
type: secp256k1

...
-----END TENDERMINT PRIVATE KEY-----
```

Only plain Cosmos `secp256k1` is accepted; `eth_secp256k1`/EVM keystores are rejected.

`nexus` can convert a 32-byte hex private key into a keystore directly:

```bash
nexus keys create-keystore --private-key-file ./private-key.txt

# When --private-key-file is omitted, the private key is also read via hidden terminal input.
# The keystore passphrase is always read twice via hidden terminal input.
export NEXUS_KEYSTORE_FILE=./builder.keystore
export NEXUS_KEYSTORE_PASSWORD_FILE=/path/to/builder.keystore.pass
```

The default output is `./builder.keystore` with mode `0600`. Existing files are never overwritten; use `--output` to pick another new path.
The account address printed on success uses the prefix configured by `NEXUS_BECH32_PREFIX`, default `trueopen`.

A compatible keystore can also be exported with the chain CLI:

```bash
<chain-cli> keys export builder --keyring-backend file > /path/to/builder.keystore

export NEXUS_KEYSTORE_FILE=/path/to/builder.keystore
export NEXUS_KEYSTORE_PASSWORD_FILE=/path/to/builder.keystore.pass
export NEXUS_BUILDER_BOND_AMOUNT=1000000

nexus start
```

The private key method is also auto-detected by Cosmos format. By default `keys export` outputs armor, which needs the passphrase used at export time; only with an explicit `--unsafe --unarmored-hex` is it raw hex:

```bash
export NEXUS_PRIVATE_KEY_FILE=/path/to/builder.key
export NEXUS_KEYSTORE_PASSWORD_FILE=/path/to/builder.key.pass

# or unsafe hex:
# <chain-cli> keys export builder --unsafe --unarmored-hex > /path/to/builder.hex
# export NEXUS_PRIVATE_KEY_FILE=/path/to/builder.hex

nexus start
```

Registration and descriptor updates use `builder register` (`nexus start` only checks, never submits):

```bash
nexus builder register
```

Phase 0's BuilderBond is fixed at zero and creates no bonded stake record (staking and slashing protocol); the wire has no
Builder bond / unbond messages, so there are no add-stake or unbond commands; admission is fixed by governance/genesis.
Builder commands print `authority_mode` and `authority_chain_id` so the target chain can be confirmed before and after an operation.

## Cross-language output stream harness

`internal/ingress/e2e_harness_test.go` (build tag `e2eharness`, not part of `make test`) starts
the real IngressAPI on a loopback TLS listener with a fake chain authority, uploads three chunks
and a Worker-signed Fin, and serves `SubscribeOutput` to an external SDK process:

```bash
E2E_OUT=/tmp/nexus-e2e.json E2E_STOP=/tmp/nexus-e2e.stop \
  go test -tags e2eharness -run '^TestE2EHarness$' ./internal/ingress/
```

The descriptor names the URL, the certificate (pin it by public key hash), session/task ids,
the Worker service public key and the fixed test user key. `session_id` and `task_id` are
IngressAPI strings (0x followed by 64 lowercase hex) to pass to `SubscribeOutput` as is; fields
ending in `_hex`, such as `task_hash_hex`, are bare hex of raw bytes, like the wire vectors, and
are not IngressAPI strings. `E2E_FIN_MODE=unsigned|badreason`
sends a Fin without a signature or with a finish_reason that does not match the signature, for
checking a subscriber's fail-closed policy. The `TRUEOPEN_OUTPUT_FIN_V1` digest itself is
`nodecontract.OutputFinSigningDigest`, pinned to the wire vectors by
`internal/nodecontract/outputfin_golden_test.go`.

## Remote Node read-only integration

Real Node addresses, chain_id and task_id are sensitive integration data and must not be written into the README, test code or commit history. When integration is needed, inject them only via the local shell, CI Secrets or an uncommitted private env file:

| Variable | Purpose |
|---|---|
| `NEXUS_CHAIN_IT_GRPC` | gRPC endpoint for latest height, `task.v1.Query/Task` read-only queries and TaskEventService subscription |
| `NEXUS_CHAIN_IT_SESSION_ID` | Sample session id; together with the task id forms the composite identity for the Task query |
| `NEXUS_CHAIN_IT_TASK_ID` | Stable sample task id used to verify the gRPC Task query |
| `NEXUS_CHAIN_IT_REST` | REST endpoint for node identity and latest block read-only preflight |
| `NEXUS_CHAIN_IT_CHAIN_ID` | Target chain ID used to validate gRPC/REST return values |

By default the remote read-only integration tests do not touch the network:

```bash
env -u NEXUS_CHAIN_IT_GRPC \
    -u NEXUS_CHAIN_IT_SESSION_ID \
    -u NEXUS_CHAIN_IT_TASK_ID \
    -u NEXUS_CHAIN_IT_REST \
    -u NEXUS_CHAIN_IT_CHAIN_ID \
    /Users/zmm/Desktop/go/bin/go test ./internal/chaincli \
    -run TestRemoteNodeReadOnlyIntegration -v -count=1
```

To run the remote read-only checks individually, first set the variables above in your local private environment, then run only the target subtests. For example:

```bash
source ./local-chain.env

/Users/zmm/Desktop/go/bin/go test ./internal/chaincli \
  -run 'TestRemoteNodeReadOnlyIntegration/(grpc_latest_height|grpc_task|rest_node_info|rest_latest_block|grpc_events)$' \
  -v -count=1
```

Success criteria:

- `grpc_latest_height` must return a non-zero latest height through the real chain client's `LatestHeight` (gRPC `GetLatestBlock`).
- `grpc_task` must first query `task.v1.Query/Task` directly with the composite identity `(session_id, task_id)`, prove that the returned assignment's `task_id` equals the sample, then return the same `TaskID` through the public `QueryTask`.
- `rest_node_info` must receive HTTP 200 with `default_node_info.network` equal to `NEXUS_CHAIN_IT_CHAIN_ID` from the private environment.
- `rest_latest_block` must receive HTTP 200 with `block.header.chain_id` equal to `NEXUS_CHAIN_IT_CHAIN_ID` from the private environment, and a non-empty latest height.
- `grpc_events` must receive one historical event with non-zero height for the sample composite key via TaskEventService `SubscribeTaskEvents`; the target node needs `NODED_TASK_EVENT_GRPC_ENABLED=true`.

Without a stable `(session_id, task_id)` sample that allows continuous read-only queries, only `grpc_task` skips or fails; the gRPC/REST read-only preflight can still run on its own. A full `nexus start`, Ingress `/healthz`, end-to-end tx events, signed broadcast, test funds, P2P verification and any chain write are not part of this round's read-only success criteria.

## Module layout

```
proto/nexus/v1 IngressAPI proto source
gen/trueopen/nexus/v1   generated: messages(*.pb.go) + nexusv1connect/ (Connect handler/client) (committed)
cmd/nexus            cobra command entry (main / root / start / version)
internal/app         composition root: dependency-ordered Start/Stop
internal/config      environment variable config (flags can override)
internal/logging     slog + lumberjack (text/json, file rotation + gzip)
internal/middleware  transport-agnostic auth / whitelist pure functions (reused by Connect interceptors)
internal/ingress     Connect IngressAPI (:8080, gRPC+gRPC-Web+HTTP/JSON) + interceptors + /healthz
internal/outputdelivery PREPARED/READY, subscribe, ACK, TTL and restart recovery for final plaintext
internal/coordinator orchestration core: verify and settle stages (InferReceipt / OpenVerify / Settle) + CortexLink downlink
internal/chaincli    node interaction (gRPC query/broadcast + resumable TaskEventService subscription + standalone height polling)
internal/relay       custody of the selected Worker's signed InferReceipt (never payload blobs), written through to kv
internal/kv          local persistence (Pebble)
internal/drain       service key rotation drain: stops new work, reports what remains
internal/ops         readiness, diagnostics, public dispatch statistics, operator files under <data_dir>/ops
internal/opsmetrics  in-process stage timings, skips and Worker outcomes of the order path
internal/localschema version and migrations of the local state layout
internal/types       shared cross-module types
```

## Next steps

1. `ingress`: add rate limiting; for k8s gRPC probes, add `connectrpc.com/grpchealth` to expose `grpc.health.v1`.

`chaincli` wiring is complete: query/broadcast, the resumable TaskEventService event stream and standalone height polling all use the configured node gRPC endpoint; in Hub mode, protocol events use the Hub gRPC endpoint.
