# Node Message Integration Notes

> Contract baseline: TrueOpen/wire `v0.2.0`, the release TrueOpen/node pins in `wire/pin.json`.
> Authoritative interface definitions: TrueOpen/node `docs/static/node-api.md` and the TrueOpen/wire protos.

Nexus currently uses only the Node's `hub.v1` and `task.v1` application-layer ABI. The proto in this repository is the exact wire mirror covering everything Nexus needs at runtime; package, message names, field numbers, field types and gRPC methods must stay identical to the Node.

## Chain boundaries

The Hub is the authoritative source for Builder identity, staking, service key, service descriptor, BuilderSet and Profile. The Task Chain is the authoritative source for task state, timeout buckets, events and task transactions.

When `hub.enabled` is on:

- `hub.*` is used for Builder registration, adding stake, updating the descriptor, unbonding, and Hub queries;
- `chain.*` is used only for Task Chain queries, event subscriptions and task transactions;
- the two chains each use their own chain ID, account sequence, gas and fee configuration.

When the Hub is not enabled, Builder management and Hub queries temporarily reuse `chain.*`, for single-chain development environments.

## Type URL

Builder management transactions:

| Operation | Type URL |
|---|---|
| Register | `/hub.v1.MsgRegisterBuilder` |
| Update descriptor | `/hub.v1.MsgUpdateServiceDescriptor` |

In Phase 0 the BuilderBond is fixed at zero; the wire has no Builder bond / unbond messages.

Task transactions:

| Stage | Type URL |
|---|---|
| Assign | `/task.v1.MsgAssign` |
| Open verify | `/task.v1.MsgOpenVerify` |
| Worker reveal | `/task.v1.MsgWorkerReveal` |
| Settle | `/task.v1.MsgSettle` |

`Any.type_url` is strictly compared against the protobuf descriptor's full name before packing. A name mismatch fails in the local prepare stage and is never broadcast.

## Queries

Hub queries:

- `/hub.v1.Query/Builder`
- `/hub.v1.Query/BuilderSet`
- `/hub.v1.Query/Params` (settlement uses `builder.settlement_builder_grace_blocks`)
- `/hub.v1.Query/ServiceKey`
- `/hub.v1.Query/ServiceDescriptor`
- `/hub.v1.Query/Profile`

Task Chain queries:

- `/task.v1.Query/Task`
- `/task.v1.Query/TaskBuilders` (the frozen Task Builder order; the right to submit settlement rotates by it)
- `/task.v1.Query/TimeoutBucket`

There is no `hub.v1.Query/StageBuilderSelection` on chain. SETTLE submission timing follows
§10.10a: rank 1 may submit at any time; after the reveal deadline, rank i has exclusive access in `(reveal+(i-1)·g, reveal+i·g]`,
where g is `settlement_builder_grace_blocks`; once all windows have passed, anyone may submit. Nexus determines the window by chain height, not the local clock.

Tasks use the composite key `(session_id, task_id)`. Nexus keeps the nested assignment, infer receipt and verifier assignment state returned by QueryTask; subsequent transactions must be constructed from these on-chain frozen values and must not substitute the latest local configuration.

`task_id` is the lowercase SHA-256 hex of the following UTF-8 literal; the session is trimmed of leading/trailing whitespace first, and this preimage does not use generic length-prefix framing:

```text
TRUEOPEN_TASK_ID_V1|<trimmed-session-id>|<decimal-order-sequence>
```

## Assign

`MsgAssign` sends the user-signed canonical order envelope and validates it item by item:

- `task_hash = H_FIELDS_V1("TRUEOPEN_TASK_ORDER_V2", canonical TaskOrderV2)`, derived from the
  `SignedOrderV2.order` the user actually signed (`nodecontract.TaskOrderHashV2`).
  Together with `task_id` (the stable RBF slot) it forms the Task's entire identity.
  The old `order_digest = sha256(order_envelope)` was removed: that was a digest of the
  envelope bytes, changing with every user signature, so the same order would yield two mutually
  unrecognizable commitments. If the transport layer needs a payload digest, use
  `BusEnvelopeV1.payload_digest` (field 20); do not call it an order/task digest;
- `SignedOrderV2` envelope: `signature_scheme` is byte-for-byte `"eip712"`, `user_signature` is
  65 bytes `R||S||V` (V ∈ {27,28}, low-S). Nexus only does shape checks
  (`nodecontract.ValidateSignedOrderEnvelopeV2`) and does not verify the signature; the legacy `secp256k1` + 64-byte
  envelope is rejected;
- fee and infer timeout must match the envelope; the envelope no longer accepts `payload_keyring_hash`;
- `selected_worker` and all other Keeper-owned fields stay empty;
- the K5 Builder rank/proof comes from the frozen Task Builder selection (`TaskBuilders`), or is computed deterministically from the same BuilderSet and stage input;
- the Builder application signature uses the service key and the `TRUEOPEN_ASSIGN_BUILDER_V1` signing frame.

The Order signature binds chain ID, owner, session ID, order sequence and the canonical envelope. Production configuration requires the SDK request envelope, and Nexus uses the signer pubkey inside it to verify the order signature at the ingress; when the relaxed dev configuration lacks that public key, the Node performs the same verification in `MsgAssign`. Neither the Worker handraise nor the Assign Builder signature binds the payload keyring any more. Old signatures are not converted or re-signed.

`tx_fee_reserve` may be zero, but must match the order.

## Open verify

`MsgOpenVerify` takes the accepted assignment and infer receipt from QueryTask as authoritative input:

- the winner must equal the on-chain selected worker;
- the Worker output must carry `output_size_bytes`; Nexus recomputes
  `infer_receipt_hash` per `TRUEOPEN_INFER_RECEIPT_V2`, using the H_FIELDS_V1 typed
  framing of Keeper Interface Contract §5.14 / §1.2 (13 fields, uint32/uint64 big-endian, Hash32 as raw 32 bytes, operator address as address
  codec bytes); see `internal/nodecontract.InferReceiptSigningDigest` for the implementation and
  `internal/nodecontract/testdata/task_domains_v1.json` for the golden vector;
- the receipt goes through `MsgSubmitInferReceipt` (§10.3) carrying the frozen `task.v1.InferReceiptV2` body;
  `chaincli.OpenVerifyTx` no longer keeps any flattened receipt string copies;
- there must be exactly three formal verifiers, and they must not include the worker;
- verifier handraise uses the Node's `TRUEOPEN_VERIFIER_HANDRAISE_SORT_V1` ordering, and the signing domain does not include the canonical output package hash;
- the K5 stage is `OPEN_VERIFY`;
- the timeout bucket and verify deadline are handled by the Node Keeper from the frozen assignment values; Nexus does not submit a deadline.

The on-chain InferReceipt contains only the receipt/output roots, size, metering and Worker service signature the Node needs for verification. `canonical_output_package_hash`, `output_cid`, `enc_key_sealed` and `output_delivery_commitment` are stored only in the Nexus `OutputRef`, for local package verification and delivery; they are not recovered from QueryTask. When the recovery flow needs these local facts and the store lacks them, it must fail closed.

Tx success only means the broadcast succeeded. State progression is still governed by Task Chain events and QueryTask.

## Worker Reveal

`MsgWorkerReveal` uses the current 8-field descriptor and submits the verify round, sampled value set hash, evidence schema version, receipt signature and optional availability endpoint hash. Nexus currently supports only the Node's v1 verify round.

## Settle

`MsgSettle` re-queries QueryTask in the prepare stage and validates the winner and the three formal verifiers. Settlement inputs are constructed per the Node canonical algorithm:

- result receipt refs hash;
- registered full result refs hash;
- payout hash;
- fault summary hash;
- evidence schema hash;
- root manifest hash;
- task evidence Merkle root.

The K5 stage is `SETTLE`. The challenge close height is computed from the Hub Profile's `challenge_open_window_blocks` and the next execution height. assignment/open-verify height, receipt/output roots, price cap and frozen fee all come from the on-chain task and the accepted order; legacy economic fields that were not frozen keep their canonical zero values.

The settlement application signature uses the service key and the `TRUEOPEN_SETTLEMENT_V1` signing frame. The current implementation only submits the optimistic `PASS` / `SETTLED_PASS` path supported by the Node.

## Keys and failure boundaries

Cosmos `SIGN_MODE_DIRECT` transactions are signed by the Builder account key. The application-level Builder signatures for Assign and Settle are signed by the service key.

A separate service keystore is the recommended configuration:

```yaml
identity:
  keystore_file: ./builder-account.key
  keystore_password_file: ./builder-account.key.pass
  service_keystore_file: ./builder-service.key
  service_keystore_password_file: ./builder-service.key.pass
```

When no service keystore is configured, the account key is temporarily reused and a warning is printed. When the account signer or a required service signer is missing, task transactions fail closed: the account sequence is not queried, and no unsigned or JSON-fallback transaction is broadcast.

## TaskEventService

Subscription requests use the `TaskEventCode`, `ProtocolEventCode` and `EventRole` enums; responses use the `item` oneof. An application event must have its code consistent with the typed payload oneof, and the `(session_id, task_id)` inside the payload must also match the outer envelope. Unknown future task event codes only trigger reconciliation via Query by composite key; legacy ABCI attributes are not parsed.

`StreamCheckpoint` only advances the opaque cursor stored in `chain_event_cursor` and produces no application `ChainEvent`. The event cursor is saved only after the event has been delivered successfully to the local consumer; an empty item, a known code/payload mismatch or an identity mismatch terminates the current stream without advancing the cursor. `OUT_OF_RANGE` still deletes the corresponding cursor and resubscribes from the latest height.

## Contract upgrades

A new wire release is a breaking change that requires a coordinated (lockstep) upgrade; no old/new dual-stack protocol is provided. Node, Nexus, the user SDK and Cortex must move to the same wire release within one release window. Upgrade steps:

1. Stop accepting new orders;
2. Drain or discard unfinished tasks created under the previous release;
3. Clean up the task and protocol cursors of the affected chains in the Nexus `chain_event_cursor` namespace;
4. Deploy Node, SDK/Cortex and Nexus built against the new wire release;
5. Restore the ingress and verify Assign, OpenVerify, checkpoint/event reconciliation and Query recovery with new tasks.

No production state converter is provided. An old SDK/Cortex must not replay orders or handraises to the new Nexus, and the new Nexus must not continue reading old opaque cursors.

## Compatibility constraints

- Changing only the Type URL while reusing other descriptors is not allowed;
- Guessing the wire layout from field names is not allowed;
- Overriding the task's frozen version with the current Profile/TimeoutBucket is not allowed;
- Advancing local task state directly on broadcast success is not allowed;
- When the Node ABI is updated, the proto mirror, generated files, mappings, canonical algorithms and descriptor/wire tests must be updated in sync.

The production source guard `TestProductionCodeHasNoLegacyNodeApplicationABI` prevents the legacy Node application ABI from re-entering `.go` or `.proto` files.
