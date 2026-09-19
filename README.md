# nexus

The off-chain coordinator process co-located with the local `node` on a TrueOpen Builder machine.
Integration notes live in `docs/`; the protocol rules live in TrueOpen/monorepo.

> Current state: a **runnable skeleton**. Module boundaries, lifecycle and the order ingress are in place;
> chaincli is wired to the local node for query / broadcast / subscription transport, while NATS / pebble can still run offline as stubs.

## Commands (cobra)

```bash
nexus start      # start the service
nexus version    # version
nexus keys create-keystore  # convert a hex private key into an encrypted keystore
nexus builder register       # ensure the Builder record and descriptor on the Hub match local config
nexus --help     # help
```

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

# Option 1: HTTP/JSON (Connect protocol, no grpcurl needed; signature fields should be built by the SDK)
curl -X POST localhost:8080/nexus.v1.IngressAPI/SubmitOrder \
  -H 'Content-Type: application/json' \
  -d '{"orderEnvelope":"<base64 canonical envelope>","payloadRef":"nexus://sha256/<64 lowercase hex>","payload":"<base64 encrypted payload>","signature":"<base64 signature>","sessionId":"<session_id>","orderSequence":"1","userAddress":"<trueopen address>","signatureScheme":"secp256k1"}'
# {"taskId":"...","accepted":true}

# Option 2: gRPC (reflection is enabled, so grpcurl needs no proto files)
grpcurl -plaintext localhost:8080 list
grpcurl -plaintext -d '{"taskId":"<task_id>"}' \
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

### Consuming the contract (`gen/trueopen` standalone module)

`gen/trueopen` is a standalone Go module (`github.com/TrueOpen/nexus/gen/trueopen`). External Go consumers
(such as Cortex) depend on it to get the IngressAPI Connect client without pulling in Nexus server dependencies.
Usage and access requirements are in [gen/trueopen/README.md](gen/trueopen/README.md).

## Node PR #85 compatibility

The current minimum compatible Node baseline is the PR #85 merge commit
`6ebe9b2f3b4ec1ca1a8b54d5de95dafc3ff673bb`. This is a breaking change that requires a coordinated (lockstep) upgrade: Node, Nexus, the user
SDK and Cortex must be deployed together; old task IDs, order / handraise / InferReceipt signatures and the legacy
TaskEventService ABI are not supported.

Before upgrading, stop the ingress and drain or discard unfinished dev tasks created under the old protocol, clear the task /
protocol event cursors of the affected dev chains, then upgrade all four components together. Nexus does not migrate old opaque cursors and does not re-sign old
orders or Cortex messages. The full wire, signatures, on-chain / local field boundaries and operating steps are in
[`docs/node-message-integration.md`](docs/node-message-integration.md).

## Interface contract alignment

The SDK-side (User) methods of `IngressAPI` follow the "Nexus↔SDK Interface Contract" v0.1;
the Worker / Verifier-side methods and the NATS layer follow the "Nexus↔Cortex Interface Contract" v0.2.

The old-to-new interface mapping, the list of breaking changes for `gen/trueopen` consumers, and how unfrozen contract items /
open disagreements are handled:

- SDK contract v0.1: [`docs/nexus-sdk-contract-migration.md`](docs/nexus-sdk-contract-migration.md)
- Cortex contract v0.2: [`docs/nexus-cortex-contract-migration.md`](docs/nexus-cortex-contract-migration.md)

The Cortex contract "target-state baseline" removed `FetchPayload`, `SubmitOutputRef`, `UploadTaskData`,
`DownloadTaskData`, `RefreshTaskDataAuthorization` and the `OutputRef` object, and added
`UploadTaskResultData`, `SubmitInferReceipt`, `SubmitVerifyCommit`, `SubmitVerifyResult`;
V1 does not issue, prepare or refresh standalone download credentials.

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
| `NEXUS_API_KEYS` | (empty) | Comma-separated list of valid api-keys; empty = no check |
| `NEXUS_IP_WHITELIST` | (empty) | Comma-separated allowed IPs/CIDRs; empty = unrestricted |
| `NEXUS_PAYLOAD_MAX_BYTES` | `16777216` | Max bytes of a single encrypted task input; also derives the Ingress message/body limit; inputs are retained until the on-chain deadline or task terminal state |
| `NEXUS_OUTPUT_REQUIRE_PLAINTEXT` | `false` | Whether outputdelivery requires plaintext; after the Cortex contract removed the Worker-side inline plaintext entry this switch has no production caller |
| `NEXUS_OUTPUT_MAX_BYTES` | `1048576` | Max bytes of a single UTF-8 plaintext output |
| `NEXUS_OUTPUT_PLAINTEXT_TTL` | `4h` | Hard retention cap for un-ACKed plaintext; on expiry it is forced unreadable and cleaned up |
| `NEXUS_OUTPUT_TOMBSTONE_TTL` | `24h` | Minimum retention for ACKed / expired / no-result tombstones |
| `NEXUS_OUTPUT_SWEEP_INTERVAL` | `1m` | Sweep interval for plaintext expiry and tombstone cleanup |
| `NEXUS_NATS_SERVERS` | (empty) | Comma-separated NATS server list; empty = stub mode |
| `NEXUS_CHAIN_GRPC` | `localhost:9090` | Task node gRPC; used for queries, tx broadcast, TaskEventService subscription and height polling |
| `NEXUS_CHAIN_ID` | `trueopen-localnet` | Chain ID |
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
| `NEXUS_BUILDER_P2P_HINT` | (empty) | NATS/P2P access hint in the Builder metadata |

## Plaintext output delivery

Warning: the Cortex contract v0.2 "target-state baseline" removed `SubmitOutputRef` and its `output_text` field:
the Worker no longer hands plaintext to the Builder; OUTPUT content always goes through `UploadTaskResultData` (persist) +
`FetchTaskData(OUTPUT)` (retrieve). `SubscribeOutput` / `AckOutput` remain RESERVED per SDK contract §3.5/§3.6,
but there is currently no production entry writing plaintext into outputdelivery, so the subscription returns
`unavailable`. The re-wiring plan is in
[`docs/nexus-cortex-contract-migration.md`](docs/nexus-cortex-contract-migration.md).

The SDK flow below describes the target state (RESERVED) and is currently unavailable:

User SDK retrieval flow:

1. Sign the `SDKRequestEnvelopeV1` for `SubscribeOutput` with the original ordering address. The method is
   `SubscribeOutput`, the endpoint is
   `/nexus.v1.IngressAPI/SubscribeOutput`, and the body digest is
   `BodyDigest(session_id, task_id)`.
2. Call the server-streaming `SubscribeOutput`. The connection waits while the output has not arrived; once it arrives it returns
   exactly one response containing `output_id/output_text/output_hash/created_at/expires_at` and ends.
3. After the SDK has durably saved the plaintext, sign and call `AckOutput`. The method is `AckOutput`, the endpoint is
   `/nexus.v1.IngressAPI/AckOutput`, and the body digest is
   `BodyDigest(session_id, task_id, output_id)`.
4. Only a successful ACK means consumption is complete. On disconnect or missing ACK, the SDK can re-subscribe and receive the same
   `output_id`; ACK is idempotent within the tombstone retention period, and repeated calls return `already_acked=true`.

These two RPCs always enforce a valid SDK envelope; even `require_sdk_envelope=false` cannot bypass it.
Nexus only allows the original ordering address to subscribe and ACK. Plaintext is written to local Pebble and is currently **not encrypted at rest**;
after the first ACK it is immediately removed from the read path and physical deletion is attempted, and un-ACKed data is
force-cleaned after the default 4-hour hard TTL. A tombstone is kept for at least 24 hours by default to block replay recovery; it contains no plaintext.
Production deployments should restrict data directory permissions, disk backup scope and operator access to the node.

## Builder registration

In Hub + Task Chain mode, `chain` always means the task chain; the Coordinator's task queries, transactions and events go through that chain. With `hub.enabled=true`, the Builder's Node Registry, stake and unbond use only `hub`. The Task Chain does not accept Builder registration transactions; identity and stake state are obtained later via Hub snapshots. Incomplete Hub configuration blocks startup and does not silently fall back to the Task Chain. Without the Hub, single-chain compatibility mode is retained and an explicit warning is printed.

Once an account signer is configured, Nexus performs Stage-1 validation on every new `SubmitOrder`. It queries this node's `ACTIVE` Builder state and the currently frozen BuilderSet in real time from the Builder registry chain, checks the `TRUEOPEN_BUILDER_SET_V1` commitment, member Bech32 addresses and term stability during the query, then reproduces the `TRUEOPEN_BUILDER_STAGE1_V1` ranking from the Task Chain ID, active term, task ID and set hash. The rank/proof produced by a successful validation is kept with the order snapshot and used directly for `AssignTx`. This computation matches trueopen-sdk's order routing and signanode's ASSIGN selection rules, and does not depend on BuilderSet return order.

During the current integration phase an observe mode is used: when this node is in the valid set but not selected, a `WARN` is logged with the stable code `NEXUS_INGRESS_NOT_SELECTED_BUILDER`; when the Hub query fails or the Builder/BuilderSet state is missing, stale, contradictory or non-canonical, `NEXUS_INGRESS_STAGE1_UNAVAILABLE` is logged. These Stage-1 failures no longer block `SubmitOrder`; the payload/FSM is still created, but no unverified rank/proof is written, and the later `AssignTx` may still be rejected by signanode with the existing submit-failure log. Signature, envelope, payload integrity, authorization and other ingress checks keep their blocking semantics. Each new order needs two Builder registry chain queries, so production must keep the corresponding gRPC endpoint available. A dev skeleton without a signer does not perform Stage-1 validation.

signanode must enable TaskEventService. Task node setting:

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

Without a stable `(session_id, task_id)` sample that allows continuous read-only queries, only `grpc_task` skips or fails; the gRPC/REST read-only preflight can still run on its own. A full `nexus start`, Ingress `/healthz`, end-to-end tx events, signed broadcast, test funds, remote NATS, P2P verification and any chain write are not part of this round's read-only success criteria.

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
internal/coordinator orchestration core: three on-chain stages (Assign / OpenVerify / Settle) + commit-reveal (FSM to be fleshed out)
internal/msgbus      NATS client (core + JetStream) + BusEnvelopeV1 sign/verify rules
internal/chaincli    node interaction (gRPC query/broadcast + resumable TaskEventService subscription + standalone height polling)
internal/relay       credential relay (keys + references, never payload blobs) — in-memory implementation
internal/kv          local persistence — in-memory implementation (pebble later)
internal/types       shared cross-module types
```

## Next steps (incremental wiring)

1. `msgbus`: wire `nats.go`, connect to the supercluster; split core/JetStream tiers. BusEnvelopeV1 and the 8 subjects of contract §5.1
   are done (`envelope_v1.go` / `subjects_v1.go`), and the `coordinator`'s
   publish/subscribe has been switched over with signing and verification attached (gh #45). **Cross-repo not yet connected**: Cortex's wire body
   still uses base64 bytes and its subject/kind still use the old vocabulary, so neither side can accept the other's frames; all four components must switch over in the same release.
   Evidence and steps are in `docs/nexus-cortex-contract-migration.md` §4.2 / §5.
2. `coordinator`: flesh out the single-order FSM (rank-based fallback settlement submission driven by chain height, handraise collection, three-stage Tx assembly, commit-reveal).
3. `kv`: switch to pebble.
4. `ingress`: add order envelope parsing + signature verification + rate limiting (gRPC-Web/HTTP-JSON are already provided by Connect); for k8s gRPC probes, add `connectrpc.com/grpchealth` to expose `grpc.health.v1`.

`chaincli` wiring is complete: query/broadcast, the resumable TaskEventService event stream and standalone height polling all use the configured node gRPC endpoint; in Hub mode, protocol events use the Hub gRPC endpoint.
