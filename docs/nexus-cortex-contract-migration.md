## Nexus<->Cortex Interface Contract Migration Mapping (v0.2)

Alignment baseline: "Nexus<->Cortex Interface Contract" v0.2 (2026-08-17, `owner: nexus-engineering`, status "under review").
Alignment targets: `service IngressAPI` in `proto/nexus/v1/ingress.proto`, and the
BusEnvelope and subject definitions in `internal/msgbus`. The starting point is `663dba5 feat(ingress): align IngressAPI with
the Nexus↔SDK contract v0.1` on `main` (the WORK-9 deliverable).

Where they conflict, the contract wins; the 9 unfrozen items in contract §8 are only recorded, not implemented, not decided.

Before alignment `IngressAPI` had 16 RPCs; after alignment it has 16 (4 removed + 4 added). This table covers:
the fate of all 16 old RPCs, the 4 additions required by contract §2, the 20 fields of BusEnvelopeV1,
and the 8 subjects and Kinds of contract §3.1.

**How "breaking" is determined**: `gen/trueopen` is an independent Go module (`github.com/TrueOpen/nexus/gen/trueopen`)
that external consumers such as Cortex depend on directly. Anything that removes an RPC, removes a message, removes a field or changes signature bytes is marked
**yes** in the "Breaking" column, and §6 aggregates them into a list that can be pasted directly into a PR.

---

### 1. IngressAPI RPC-level mapping

| Old RPC | New RPC | Change type | Basis (contract section) | Breaking (gen/trueopen) | Notes |
|---|---|---|---|---|---|
| `FetchPayload` | None (taken over by `FetchTaskData(INPUT)`) | Removed | Target-state baseline / §2.2 | **Yes** | Request/response messages removed together; the selected Worker fetches INPUT with a range signature |
| `SubmitOutputRef` | None (split into `SubmitInferReceipt` + `UploadTaskResultData`) | Removed | Target-state baseline / §2.1 / §2.4 | **Yes** | The receipt and the large object take separate paths; inline `output_text` retires with it |
| `UploadTaskData` (client stream) | `UploadTaskResultData` (client stream) | Renamed + field changes | §2.1 | **Yes** | Method name, header/response message names and the method binding in `RequestSignBytes` all change |
| `DownloadTaskData` | (already renamed to `FetchTaskData` in WORK-9) | Unchanged | §2.2 | No | No second rename in this round |
| `RefreshTaskDataAuthorization` | None | Removed | Target-state baseline / §2.2 | **Yes** | V1 does not issue, prepare or refresh standalone download credentials |
| — | `UploadTaskResultData` | Added | §2.1 | No (new) | OUTPUT / EVIDENCE are uploaded and stored separately; returns the Builder storage confirmation |
| — | `SubmitInferReceipt` | Added | §2.4 | No (new) | Acceptance means the Builder commits to relaying it; does not wait for the output/evidence upload |
| — | `SubmitVerifyCommit` | Added; initial relay implementation changed to carry the on-chain `VerifyCommitV1` body | §2.5 | **Yes** (Cortex-facing field set changed) | After validating the request and the role signature, relays via `MsgBatchSubmitVerifyCommit`; the response only means broadcast (see §4-B) |
| — | `SubmitVerifyResult` | Added; initial relay implementation changed to carry the on-chain `ResultReceiptV1` body | §2.6 | **Yes** (Cortex-facing field set changed) | Same as above, relayed via `MsgBatchSubmitVerifyResult`; the same receipt as the VERIFY_RESULT JetStream path (see §4-B) |
| `OpenTask` (client stream) | `OpenTask` | Unchanged | SDK contract §3.1 | No | This contract does not cover the SDK ordering path |
| `ConfirmOpenTask` | `ConfirmOpenTask` | Unchanged | SDK contract §3.2 / §8.3 | No | Returns `FailedPrecondition` + `NEXUS_INGRESS_CONTRACT_NOT_FROZEN`, pending the freeze of the §8.2 field table and the §8.3 storage confirmation encoding (freeze date to be given by the protocol owner) |
| `GetTaskDataMetadata` | `GetTaskDataMetadata` | Field changes | §2.3 | **Yes** | Removed `download_authorization` (now `reserved 2`) |
| `FetchTaskData` (server stream) | `FetchTaskData` | Field changes + semantic changes | §2.2 | **Yes** | Removed `authorization` from the request (`reserved 5`); authorization is decided solely by the on-chain role |
| `SubscribeOutput` (server stream) | `SubscribeOutput` | Semantic change | SDK contract §3.5 (RESERVED) | No (wire unchanged) | After the plaintext entry point retires with `SubmitOutputRef` there is no producing writer; see §5 |
| `AckOutput` | `AckOutput` | Unchanged | SDK contract §3.6 (RESERVED) | No | Same as above |
| `GetTaskStatus` | `GetTaskStatus` | Unchanged | SDK contract §3.7 | No | — |
| `GetTaskEvents` (server stream) | `GetTaskEvents` | Unchanged | SDK contract §3.8 | No | See §3 for `event_code` value differences |
| `PrepareChallenge` | `PrepareChallenge` | Unchanged | SDK contract §3.9 | No | — |
| `SubmitOrder` | None (taken over by `OpenTask`) | To be confirmed | SDK contract §3.1 | **Yes** if removed | Still `deprecated`; **not** on this contract's decision list |
| `FetchOutputRef` | Only `CredentialV1` remains | To be confirmed + field changes | Target-state baseline | **Yes** (field removed) | Removed `output_ref` (`reserved 1`); whether the RPC itself stays is pending decision |
| `RefreshCredential` | Only `CredentialV1` remains | To be confirmed + field changes | Target-state baseline | **Yes** (field removed) | Removed `output_ref` (`reserved 2`); the contract's "V1 does not refresh standalone download credentials" conflicts with keeping this method, pending decision |

All 6 method origins in contract §2 are covered: `UploadTaskResultData`<-`UploadTaskData`;
`FetchTaskData`<-`DownloadTaskData` (WORK-9); `GetTaskDataMetadata`<-same name;
`SubmitInferReceipt` / `SubmitVerifyCommit` / `SubmitVerifyResult`<-added.

### 2. IngressAPI message / field-level mapping

| Old message / field | New message / field | Change type | Basis | Breaking | Notes |
|---|---|---|---|---|---|
| `FetchPayloadRequest` / `FetchPayloadResponse` | None | Removed | Target-state baseline | **Yes** | Removed together with `FetchPayload` |
| `SubmitOutputRefRequest` / `SubmitOutputRefResponse` | None | Removed | Target-state baseline | **Yes** | Removed together with `SubmitOutputRef` |
| `SubmitOutputRefRequest.output_cid` / `.enc_key_sealed` | None | Removed | Target-state baseline / §5 | **Yes** | The storage confirmation contains no local path, CID, endpoint, chunk position or locator |
| `SubmitOutputRefRequest.canonical_output_package_hash` | None | Removed | §9 check item 1 | **Yes** | The package-integrity commitment from the three-hash split retires entirely |
| `SubmitOutputRefRequest.output_delivery_commitment` | None | Removed | §9 check item 1 | **Yes** | Same as above (the `delivery_output_hash` family) |
| `SubmitOutputRefRequest.output_text` | None | Removed | Target-state baseline | **Yes** | SDK plaintext delivery moves to `FetchTaskData(OUTPUT)` |
| `UploadTaskDataHeader` | `UploadTaskResultDataHeader` | Renamed + field added | §2.1 | **Yes** | Added `evidence_type` (field 10); required for EVIDENCE |
| `UploadTaskDataRequest` / `Response` | `UploadTaskResultDataRequest` / `Response` | Renamed + field added | §2.1 | **Yes** | Response adds `storage_confirmation` (field 4) |
| — | `BuilderStorageConfirmationV1` | Added | §2.1 / §5 | No (new) | Field set = §5 semantic signing scope; name/field numbers/encoding not frozen (§8.3) |
| — | `EvidenceCommitmentV1` | Added (reshaped again this round) | §2.4 / Keeper §5.14 | **Yes** (relative to the previous round) | The free-string triple `{evidence_type, commitment, size_bytes}` is replaced by the frozen shape `{EvidenceKind evidence_kind, bytes evidence_hash_or_root, uint64 encoded_size_bytes}` and moved from request level into the receipt (field 10). Details in §10 |
| — | `SubmitInferReceiptRequest` / `Response` | Added | §2.4 | No (new) | `relay_accepted` explicitly means only that the Builder commits to relaying it |
| — | `SubmitVerifyCommitRequest` / `Response` | Added | §2.5 | No (new) | No `verdict` field (asserted by tests) |
| — | `SubmitVerifyResultRequest` / `Response` | Added | §2.6 | No (new) | No `verdict` / `sample_values` / `sample_seed` / `evidence_ref` (asserted by tests) |
| — | `VerifyMetricSummaryV1` | Added | §2.6 | No (new) | Typed metric_summary; the contract only says "typed" and gives no field table (see §4-A item 5) |
| `OutputRef` (message) | None | Removed | Target-state baseline | **Yes** | The object is removed entirely; no compatibility structure kept |
| `TaskDataAuthorizationV1` | None | Removed | Target-state baseline / §2.2 | **Yes** | The pre-signed download credential route is removed entirely |
| `RefreshTaskDataAuthorizationRequest` / `Response` | None | Removed | Target-state baseline | **Yes** | Same as above |
| `FetchTaskDataRequest.authorization` | None (`reserved 5`) | Removed | §2.2 | **Yes** | "Nexus verifies the current service key and the on-chain role on the spot; no pre-signed download credentials" |
| `GetTaskDataMetadataResponse.download_authorization` | None (`reserved 2`) | Removed | §2.3 | **Yes** | "Does not return actual content, Builder-internal locators or download authorization" |
| `FetchOutputRefResponse.output_ref` | None (`reserved 1`) | Removed | Target-state baseline | **Yes** | See notes in §1 |
| `RefreshCredentialResponse.output_ref` | None (`reserved 2`) | Removed | Target-state baseline | **Yes** | See notes in §1 |
| `SignedTaskDataRangeV1` (unchanged) | Same name | Semantic change | §2.2 / §8.4 | **Yes** (signature bytes change) | `RangeSignBytes` no longer binds `authorization_id`; it now binds `chain_id` + `builder_address` + Task + `data_kind` + selector + range + validity + nonce |
| `TaskDataRequestAuthV1` (unchanged) | Same name | Semantic change | §1.3 / §8.2 | **Yes** (method renamed) | Now also serves as the Worker/Verifier role-signature carrier; the `MethodUpload` string `UploadTaskData`->`UploadTaskResultData` enters the signature bytes |
| `SignedInferReceiptV1` (unchanged) | Same name | **Field set and field numbers reshaped wholesale** | §2.4 / Keeper §5.14 | **Yes** (both signature bytes and field numbers change) | Switched to the frozen `task.v1.InferReceiptV1`: added `schema_version` / `chain_id` / `task_hash` / `service_authorization_nonce` / `generation_params_digest` / `expiry_height` / `required_evidence_commitments`, removed `infer_receipt_commit_hash` / `infer_receipt_hash` / `trace_commit_root` / `checkpoint_commit_root` / `batch_log_root` / `token_count` / `work_unit`, field numbers renumbered to align with Node. Details in §10 |
| `CredentialV1` / `AccessLevel` | Same name | To be confirmed | Target-state baseline | No (not removed this round) | The contract says V1 issues no standalone download credentials, but `FetchOutputRef`/`RefreshCredential` are not on the decision list, so they are kept |

### 3. Internal types and event codes (not wire, but externally observable)

| Old | New | Change type | Basis | Breaking | Notes |
|---|---|---|---|---|---|
| `types.OutputRef` | `types.InferReceiptSubmission` | Renamed + field changes | Target-state baseline / §2.4 / Keeper §5.14 | No (internal) | Removed `OutputCID` / `EncKeySealed` / `CanonicalOutputPackageHash` / `OutputDeliveryCommitment` / `WorkerSig`; then removed `InferReceiptCommitHash` / `TraceCommitRoot` / `CheckpointCommitRoot` / `BatchLogRoot` / `TokenCount` / `WorkUnit`; added `SchemaVersion` / `ChainID` / `TaskHash` / `ServiceAuthorizationNonce` / `GenerationParamsDigest` / `ExpiryHeight` / typed `EvidenceCommitments`. `InferReceiptHash` becomes a locally derived value |
| `ingress.Handler.OnOutputRef(ref, outputText)` | `OnInferReceipt(receipt)` | Renamed + field changes | §2.4 | No (internal) | No longer receives inline plaintext |
| `Handler.FetchPayload` | None | Removed | Target-state baseline | No (internal) | — |
| `Handler.FetchOutputRef` -> `(OutputRef, Credential)` | -> `(Credential)` | Field changes | Target-state baseline | No (internal) | — |
| `Handler.RefreshCredential` -> `(Credential, OutputRef)` | -> `(Credential)` | Field changes | Target-state baseline | No (internal) | — |
| `taskdata.Authorization` + `issue()` + `Refresh()` | `Authorizer.AuthorizeDownload(key, range)` | Removed + added | §2.2 | No (internal) | Also removes the `kv.NSTaskDataAuthorization` namespace and its cleanup logic |
| — | `taskdata.StorageConfirmation` + `ConfirmationSignBytes` | Added | §5 | No (internal) | Idempotency key = material digest + builder operator |
| `config.TaskDataConfig.AuthorizationTTLBlocks` | `RetentionLeaseBlocks` | Renamed + semantic change | §5 | **Yes** (config key) | yaml `authorization_ttl_blocks`->`retention_lease_blocks`; env `NEXUS_TASK_DATA_AUTHORIZATION_TTL_BLOCKS`->`NEXUS_TASK_DATA_RETENTION_LEASE_BLOCKS` |
| `taskSnapshot.output_ref` / `output_pkg_hash` / `output_cid` | `taskSnapshot.infer_receipt` | Renamed + removed | §2.4 | **Yes** (local snapshot) | These keys in old snapshots are no longer read: a clean state or a one-off migration is needed after upgrade; restore behavior in §5 |
| `EvOutputRefReceived` (Go constant) | `EvInferReceiptReceived` | Renamed | §9 check item 1 | No (internal) | **The wire value is still `OUTPUT_REF_RECEIVED`**: that string belongs to the event_code set frozen by SDK contract §3.8, which conflicts with Cortex §9 "OutputRef must no longer appear in code"; **to be confirmed** |

### 4. NATS layer

#### 4.1 The 20 fixed fields of BusEnvelopeV1 (contract §5.2)

Implemented in `internal/msgbus/envelope_v1.go`, wired in `internal/coordinator/busenvelope.go`.
The old envelope `msgbus.BusEnvelope` (14 fields) and its bare `json.Unmarshal` decode path were
**removed** with gh #45: in the contract `BusEnvelopeV1` is the only permitted envelope, and dual-writing would again blur "which one is authoritative".

Section numbering: after the monorepo "Interface & Topic Catalogue" was renumbered, the 20-field table is §5.2, the subject list §5.1,
and the SenderRole matrix §5.3. The §3.2/§3.1/§3.3 references in earlier parts of this document refer to the same tables.

| # | Contract field | Old envelope field | Change type | Notes |
|---|---|---|---|---|
| 1 | `schema_version` | `schema_version` | Semantic change | Fixed `1`, not "starting from 1" |
| 2 | `chain_id` | `chain_id` | Unchanged | Must equal the local Task Chain |
| 3 | `subject` | `subject` | Unchanged | Must be byte-for-byte equal to the actual NATS subject |
| 4 | `kind` | `kind` | Field change | Value domain replaced by the 8 Kinds of §3.1 (the old 9 are in §4.3) |
| 5 | `sender_participant_type` | — | Added | `BUILDER`/`CORTEX`; determines the current service key lookup domain |
| 6 | `sender_operator_address` | `sender_id` | Renamed | Stable bech32 protocol identity |
| 7 | `service_authorization_nonce` | — | Added | Must match the current service binding at verification time |
| 8 | `sender_role` | `sender_role` | Field change | Value domain drops `SDK`, leaving only `BUILDER`/`WORKER`/`VERIFIER` |
| 9 | `session_id` | `session_id` | Unchanged | Required for task messages |
| 10 | `task_id` | `task_id` | Semantic change | The contract requires it non-empty for task-scoped messages (the old comment allowed it empty at model level) |
| 11 | `builder_set_id` | — | Added | Must match the BuilderSet locked by Open Task |
| 12 | `builder_set_hash` | — | Added | Same as above |
| 13 | `stage` | `stage` (only inside the prepare payload) | Field change | Promoted to an envelope field; values `OPEN_TASK`/`OPEN_VERIFY`/`SETTLE` (the old `ASSIGN` disappears) |
| 14 | `source_snapshot_height` | — | Added | The sender's chain view; not used for historical key lookups |
| 15 | `message_id` | `message_id` | Semantic change | Must be UUIDv7 (the old implementation used UUIDv4) |
| 16 | `nonce` | `nonce` | Unchanged | 32 bytes CSPRNG, reused on retry |
| 17 | `issued_at_unix_ms` | `issued_at` | Renamed | Unit made explicit in the field name |
| 18 | `expires_at_unix_ms` | `expires_at` | Renamed | Redelivery neither refreshes nor re-signs |
| 19 | `payload_codec` | — | Added | Fixed `trueopen-cjson-v1` |
| 20 | `payload_digest` | — | Added | `SHA256(PAYLOAD_BYTES)` |
| — | `payload` | `payload` | Semantic change | Must be canonical JSON, bound by the digest, not part of the signed field sequence |
| — | `signature` | `signature` | Semantic change | 64B compact low-S `R‖S`; rejects DER / 65-byte recoverable / high-S |

Signing and verification:

- `SIGN_BYTES = FRAME_V1("TRUEOPEN_BUS_ENVELOPE_V1", trueopen_cjson_v1(fields 1..20))`,
  `SIGN_DIGEST = SHA256(SIGN_BYTES)` (`SignBytesV1` / `SignDigestV1`, locked by tests).
  `FRAME_V1` uses the single-payload framing frozen in Keeper Interface Contract §1.2 (corrected by issue #37):
  `ascii("TRUEOPEN_FRAME_V1") || u32be(len(domain)) || domain || u64be(len(payload)) || payload`,
  which is **not** the same layout as the local 4-byte length-prefixed frames in `internal/sdkauth` and `internal/taskdata`.
- The fixed 8-step verification order is implemented by `VerifyV1`, with one assertable error per step (`ErrEnvelopeStructure` ->
  `ErrEnvelopeRouting` -> `ErrEnvelopeChainFresh` -> `ErrEnvelopePayload` ->
  `ErrEnvelopeBuilderSet` -> `ErrEnvelopeServiceBind` -> `ErrEnvelopeSignature` ->
  `ErrEnvelopeReplay`); for every step the tests construct a case where "this step and later steps are broken at the same time"
  and assert that this step is reported first.
- Dual-key replay store: `(chain_id, sender_operator, authorization_nonce, message_id)` and
  `(..., nonce)`, recording `SIGN_DIGEST`; same key with the same digest is a legitimate retry, a different digest is
  replay/conflict; tombstones are kept until `expires_at_unix_ms + local_replay_safety_margin`.
- `Nats-Msg-Id = message_id` (`NatsMsgID()`), JetStream stream `TRUEOPEN_TASK`.

#### 4.2 Subject list (contract §5.1)

`internal/msgbus/subjects_v1.go` is the **only** list; the old `subjects.go` was removed with gh #45.

| Contract subject | Kind | Tier | Old subject | Change type |
|---|---|---|---|---|
| `trueopen.task.open.<model_id>` | `OPEN_TASK` | Core | `trueopen.orders.<model_id>` | Renamed |
| `trueopen.handraise.worker.<task_id>` | `WORKER_HANDRAISE` | Core | Same name | Unchanged |
| `trueopen.verify.open.<task_id>` | `OPEN_VERIFY` | Core | `trueopen.verify-select.<task_id>` (JetStream) | Renamed + semantic change (tier changed to Core; semantics changed from "selection notice" to "open-verify broadcast") |
| `trueopen.handraise.verifier.<task_id>` | `VERIFIER_HANDRAISE` | Core | Same name | Unchanged |
| `trueopen.worker-assignment.<task_id>` | `WORKER_ASSIGNMENT_NOTIFY` | JetStream | `trueopen.assign.<task_id>` | Renamed |
| `trueopen.output-avail.<task_id>` | `OUTPUT_AVAILABLE` | JetStream | Same name | Field change (payload drops `output_cid` and the package hash) |
| `trueopen.verifier-assignment.<task_id>` | `VERIFIER_ASSIGNMENT_NOTIFY` | JetStream | None (the old `verify-select` mixed broadcast with assignment) | Added |
| `trueopen.verify-result.<task_id>` | `VERIFY_RESULT` | JetStream | Same name | Field change (payload in §4.4) |
| — | — | — | `trueopen.sample-ready.<task_id>` | **Removed** (contract §5.9: in V1 the selected Verifier recomputes all committed tokens; the notification carries no sampling data). The on-chain `SampleReady` event still records the local seed and phase, it just no longer goes onto NATS |
| `nexus.builder-prepare.<task_id>` | `BUILDER_PREPARE` | Core (internal) | `trueopen.prepare.<task_id>` | **Moved out of the trueopen.\* namespace** (recommended in gh #45, to be confirmed): the table in contract §5.1 is a closed set, and an implementation must not add entries to the protocol on its own. It is a Builder<->Builder de-duplication announcement that Cortex neither sends nor receives, but it still goes through the same BusEnvelopeV1 signing/verification |
| — | — | — | `trueopen.orders.*` / `trueopen.assign.<task_id>` | Removed (the contract explicitly says they "do not exist") |

`LookupSubjectV1` rejects old subjects, wildcards and multi-level placeholders without exception (locked by tests).
The JetStream stream-creation wildcards are derived from the same table by `JetStreamSubjectWildcardsV1()`;
`natsbus.go` no longer keeps its own copy.

##### JetStream stream migration (operational action, performed manually)

gh #45 switched the subjects of `TRUEOPEN_TASK` from the old list to the v1 list. **The code does not delete an existing stream**
(deleting the stream would also lose in-flight messages and all durable consumer positions): `ensureStreams` first calls `AddStream`,
and if the stream exists it calls `UpdateStream` to change the subjects in place, emitting a WARN that manual handling is needed.

| Old subject (no longer received by the stream) | v1 subject |
|---|---|
| `trueopen.assign.*` | `trueopen.worker-assignment.*` |
| `trueopen.verify-select.*` | `trueopen.verifier-assignment.*` |
| `trueopen.sample-ready.*` | None (retired) |
| `trueopen.output-avail.*` / `trueopen.verify-result.*` | Same name, unchanged |

Recommended steps (same for devnet and production):

1. Stop nexus (Ctrl-C in the `screen` session, or kill) and confirm there are no more new publishes.
2. Record the current subjects, message counts and consumer list with `nats stream info TRUEOPEN_TASK`.
3. Confirm there are **no unconsumed in-flight messages** on the old subjects:
   inspect them one by one with `nats stream view TRUEOPEN_TASK --subject 'trueopen.assign.*'` etc.
   If there are in-flight messages, let the old nexus version drain them before upgrading -- the new version no longer subscribes to the old subjects.
4. Update the subjects in place: `nats stream edit TRUEOPEN_TASK --subjects 'trueopen.worker-assignment.*,trueopen.output-avail.*,trueopen.verifier-assignment.*,trueopen.verify-result.*'`
   (or simply start the new nexus version and let `UpdateStream` in `ensureStreams` do the same thing).
5. **Existing durable consumers**: the filter subject of `nexus-<node_id>-vr-<task_id>` is
   `trueopen.verify-result.<task_id>`; neither name nor subject changed, positions are kept as-is, nothing to do.
   Consumers filtering on retired subjects (if the deployer created their own) must be deleted:
   `nats consumer rm TRUEOPEN_TASK <name>` -- their filters are not among the new subjects and they would idle forever.
6. Start the new nexus version and re-check with `nats stream info TRUEOPEN_TASK` that the subjects are the four v1 entries.

If you would rather have a clean state than keep in-flight messages, deleting and recreating the stream also works
(`nats stream rm TRUEOPEN_TASK`; on next start `AddStream` recreates it from the v1 list),
at the cost of losing all unconsumed `VERIFY_RESULT` messages and all consumer positions --
those messages can be re-sent by Verifiers, but that needs cooperation from the Cortex side; do not do it unattended.

#### 4.3 Kind and SenderRole matrix (contract §3.3)

| Old Kind | New Kind | Change type | participant_type / sender_role |
|---|---|---|---|
| `ORDER_BROADCAST` | `OPEN_TASK` | Renamed | BUILDER / BUILDER |
| `WORKER_HANDRAISE` | `WORKER_HANDRAISE` | Unchanged | CORTEX / WORKER |
| `VERIFIER_HANDRAISE` | `VERIFIER_HANDRAISE` | Unchanged | CORTEX / VERIFIER |
| `ASSIGN_NOTIFY` | `WORKER_ASSIGNMENT_NOTIFY` | Renamed | BUILDER / BUILDER |
| `VERIFY_SELECT_NOTIFY` | `OPEN_VERIFY` + `VERIFIER_ASSIGNMENT_NOTIFY` | Split | BUILDER / BUILDER |
| `OUTPUT_AVAILABLE` | `OUTPUT_AVAILABLE` | Unchanged | CORTEX+WORKER or BUILDER+BUILDER (the only multi-sender Kind) |
| `VERIFY_RESULT` | `VERIFY_RESULT` | Field change | CORTEX / VERIFIER |
| `SAMPLE_READY_NOTIFY` | None | Removed | The contract has no plain sample seed |
| `ASSIGN_PREPARE` | None | To be confirmed | Not listed in contract §3.1/§3.3 |

Unknown combinations must be rejected (`AllowedSenderV1`; tests cover both the allowed and the rejected side).

#### 4.4 Changed NATS payloads (`internal/msgbus/messages.go`)

| Old field | New | Change type | Basis |
|---|---|---|---|
| `VerifierHandraise.canonical_output_package_hash` | None | Removed | §4.6 |
| `VerifierHandraise.package_auth_checked` | None | Removed | §4.6 (no more package-fetch pre-check declaration) |
| `OutputAvailable.output_cid` | None | Removed | §4.4 |
| `OutputAvailable.canonical_output_package_hash` | None | Removed | §4.4 / §9 check item 1 |
| `VerifySelectNotify.output_cid` / `.canonical_output_package_hash` | None | Removed | §4.7 |
| `VerifyResult.sample_values` / `.salt` / `.evidence_ref` | To be confirmed (not removed) | To be confirmed | §2.6 / §9 check item 6; removal would also change the settlement FSM, see §5 |

Correspondingly, `taskFSM.validVerifierHandraise` no longer compares the package hash, only `output_hash` and
`infer_receipt_hash` (§4.6); `validateReceiptForOpenVerify` no longer requires
`canonical_output_package_hash` and `output_delivery_commitment`.

#### 4.5 Encoding of bytes fields in payloads: base64 -> bare lowercase hex (§3.1)

The payload structs used to have 10 `[]byte` fields. `encoding/json` encodes `[]byte` as
**base64**, while §3.1 requires hashes and signatures to be canonical lowercase hex, so these fields as sent by nexus itself
had the same bug as Cortex (see §5 "Not completed this round", item 1). They did not
blow up earlier only because the hand-raise message was the first one to reach the payload-decoding step.

| Struct | Fields |
|---|---|
| `VerifierHandraise` | `output_hash`, `signature` |
| `WorkerAssignmentNotify` | `assign_seed` |
| `OutputAvailable` | `output_hash` |
| `VerifierAssignmentNotify` | `output_hash` |
| `OpenVerify` | `output_hash` |
| `VerifyResult` | `result_commit_hash`, `sample_values` (`[][]byte` -> `[]string`, element-wise hex), `salt`, `verifier_sig` |

They are now all `string`, holding bare lowercase hex without `0x` -- the same convention as the reworked `WorkerHandraise` of §5.5,
so reading the code does not require remembering two rule sets. **The envelope layer is untouched**: the `0x` hex used by `BusEnvelopeV1`'s `nonce` /
`payload_digest` / `signature` / `builder_set_hash` is explicitly specified in §5.2,
and both sides already match byte for byte. The signature preimages are untouched too: encoding is a wire matter, and the digest definitions are given by Keeper Interface
Contract §4.1 and others.

Read sites use `msgbus.IsPayloadHexV1` as a fail-closed encoding check, and the logs separate "wrong encoding" from
"wrong value bound" into two lines -- this bug was hard to find precisely because the two were mixed together. Regression is guarded permanently by
`internal/msgbus/payload_hex_test.go`: one test asserts the character set and length on the wire,
one scans the payload structs with reflect and **fails as soon as anyone writes `[]byte` again**, so there is no need to wait for integration testing
to hit the wall.

The upgrade path has two gates, because base64 from old snapshots decodes into `string` fields silently:

1. **Version gate** -- snapshot version `2 -> 3` (`snapshotVersionHexPayloadV3`); `restoreFrom`
   discards the entire pre-v3 `verify_results` / `verifier_handraises` sections and logs a warn.
   base64 -> hex is a known encoding format migration, and a version number states it most directly; this is also the first time the `Version`
   field truly carries weight -- before this, `save()` always wrote a hard-coded `2` and `restoreFrom` never read it.
2. **Encoding gate** -- even when the version matches, every field is still checked with `msgbus.IsPayloadHexV1`. The version number only proves
   "the code version that wrote it intended to write hex"; it does not prove the field really is hex.

Either gate alone is insufficient: with only the encoding gate, short pre-v3 values that happen to pass (base64 and hex character sets overlap)
would slip through; with only the version gate, any encoding regression after v3 would pass straight through. Dropping these caches is safe --
hand-raises are re-sent, V_i goes through JetStream replay, and the snapshot itself is only a non-authoritative cache.

---

### 5. Phase boundary: what this round changed and what it did not

Completed this round (code + tests):

1. The IngressAPI removal decisions and the 4 added RPCs (§1 / §2).
2. Retirement of pre-signed download credentials: `Authorization` / `issue` / `Refresh` /
   `NSTaskDataAuthorization` in `taskdata` all removed; `FetchTaskData` changed to self-signed range + on-chain role authorization.
3. Builder storage confirmation (§5 semantic scope) implemented and returned with the upload response.
4. The BusEnvelopeV1 structure, `trueopen-cjson-v1` encoding, `SIGN_BYTES`, the 8-step verification order,
   the dual-key replay store, and the 8 subjects of §5.1 + the §5.3 matrix.
5. (gh #45) The coordinator's publish/subscribe switched to v1 subjects + BusEnvelopeV1; outbound signed with the current
   service key, inbound passed through `VerifyV1` (including low-S enforcement and the replay store); the old envelope and old
   subjects removed together; `cmd/mock-cortex` upgraded in step; cross-repo signature vectors landed as permanent regression tests.

**Not** completed this round (deliberately left; members need to decide priority):

1. **The Cortex side has not been upgraded yet (cross-repo blocker; nexus cannot change it unilaterally)**. Verified against `TrueOpen/cortex@d312b00`
   `internal/builderclient/`:
   - The wire body in `envelope.go` is `json.Marshal(BusEnvelope)`, encoding bytes fields as
     **base64**, whereas contract §5.2 and this repository's `EncodeV1` use `trueopen-cjson-v1` + `0x` hex.
     Cortex's own comment says "the divergence is on the nexus side and is tracked
     separately", but per the monorepo documents §5.2 is the authority. **Neither side can accept the other's frames**
     until one side changes its wire encoding. The signing domains already match byte for byte on both sides (see below).
   - The subjects and kinds in `nats.go` / `envelope.go` are still the pre-rename vocabulary
     (`trueopen.orders.*`/`ORDER_BROADCAST`, `trueopen.assign.*`/`ASSIGN_NOTIFY`,
     `trueopen.verify-select.*`/`VERIFY_SELECT_NOTIFY`, `trueopen.sample-ready.*`),
     with no `trueopen.task.open.*` / `OPEN_TASK` / `trueopen.verify.open.*`.
   - `DecodePayload` uses `DisallowUnknownFields`, and §5.2 requires the receiver to re-canonical-encode
     and compare, so the payload field sets must also match on both sides before the application layer can move.
   Therefore **the acceptance criterion "one real frame accepted by Cortex in strict mode" cannot be met within this repository**; Cortex must
   switch its wire encoding + subject/kind vocabulary in step, with all four components upgrading together in lockstep (which is exactly what the contract §5.2 version-migration rule
   says: "V1 is not yet deployed; hard-switch as a whole at launch").
2. **The replay store is still an in-process implementation** (`MemoryReplayStoreV1`): tombstones are lost on restart.
   Only after switching to `internal/kv` (pebble) can it survive restarts; this is a §5 follow-up item.
3. **No publisher outbox**. Contract §5.1 requires that "network retries must reuse the exact
   envelope bytes persisted the first time and the same message_id"; currently every publish generates a new `message_id`/`nonce`,
   and the process does not re-send, so in practice each message is sent exactly once. Real at-least-once re-sending needs an outbox first.
4. **The sampling route is still present**: `WorkerReveal`, `VerifyResult.sample_values` and
   the `minConsistentVerifyResults` settlement decision are still in the coordinator (hence §9 check item 6 is non-compliant).
   This chain is also constrained by the Node baseline (`WorkerRevealTx` / `FullResultRevealState` are both on-chain),
   so all four components must change in the same release.
5. **SDK plaintext delivery currently has no input source**. The contract removed the Worker-side inline plaintext entry; on the SDK side
   `SubscribeOutput`/`AckOutput` remain RESERVED, and the target state is `FetchTaskData(OUTPUT)`.
   The `outputdelivery` package and its unit tests are kept as-is; the coordinator-side delivery tests switched to an internal seam
   (`deliverPlaintext`, whose comment states which removed entry point it stands in for).
   Impact: `SubscribeOutput` currently returns `unavailable`.
6. **Local snapshots are incompatible**: `taskSnapshot`'s `output_ref`/`output_pkg_hash`/`output_cid` are replaced by
   `infer_receipt`. When old snapshots are restored these fields cannot be read (affected tasks lack receipt data
   and cannot assemble OpenVerifyTx). A clean state or a one-off migration is needed before deployment.

Coverage changes (recorded as-is): removed `taskdata`'s
`TestSweepWaitsForAuthorizationIssuanceAndRemovesRecord` (the authorization issue/cleanup race under test disappeared with
the authorization object); `TestAuthorizationRefreshUsesDurableIssuanceRecord` and
`TestAuthorizationAndRangeSignBytesGolden` were replaced by `TestAuthorizeDownloadRangeReplayAndRoleChange`,
`TestRangeSignBytesBindsContractFields`, `TestSignStorageConfirmation` and
`TestConfirmationSignBytesAndDigest`; on the ingress side the behavior tests for `FetchPayload` and
`SubmitOutputRef` were removed, and `internal/ingress/workerverifier_test.go` was added
(receipt binding / malformed input / error mapping + commit/result validation).

---

### 6. Breaking-change list for external consumers of `gen/trueopen`

`gen/trueopen` is an independent Go module that Cortex depends on directly. Every item below will make existing Cortex code fail to compile or
change behavior, and requires Node / Nexus / user SDK / Cortex to move in sync (mandatory rule 3):

**Removed RPCs (4)**: `FetchPayload`, `SubmitOutputRef`, `UploadTaskData`,
`RefreshTaskDataAuthorization`.

**Removed messages (11)**: `FetchPayloadRequest`, `FetchPayloadResponse`,
`SubmitOutputRefRequest`, `SubmitOutputRefResponse`, `UploadTaskDataHeader`,
`UploadTaskDataRequest`, `UploadTaskDataResponse`, `RefreshTaskDataAuthorizationRequest`,
`RefreshTaskDataAuthorizationResponse`, `OutputRef`, `TaskDataAuthorizationV1`.

**Removed fields (4)**: `GetTaskDataMetadataResponse.download_authorization` (reserved 2),
`FetchTaskDataRequest.authorization` (reserved 5), `FetchOutputRefResponse.output_ref`
(reserved 1), `RefreshCredentialResponse.output_ref` (reserved 2).

**Changed signature bytes (2)**:
- `RangeSignBytes`: no longer binds `authorization_id`; binds `chain_id`/`builder_address` instead;
  old range signatures always fail on the new server.
- The method binding in `RequestSignBytes`: upload method name `UploadTaskData` -> `UploadTaskResultData`.

**Added (does not break compilation, but requires Cortex implementation)**: `UploadTaskResultData`, `SubmitInferReceipt`,
`SubmitVerifyCommit`, `SubmitVerifyResult` and their messages, `BuilderStorageConfirmationV1`,
`EvidenceCommitmentV1`, `VerifyMetricSummaryV1`.

**Renamed config keys (deployment side)**: `authorization_ttl_blocks` -> `retention_lease_blocks`;
`NEXUS_TASK_DATA_AUTHORIZATION_TTL_BLOCKS` -> `NEXUS_TASK_DATA_RETENTION_LEASE_BLOCKS`.

---

### 7. Hand-off from WORK-9 (SDK contract v0.1)

WORK-9 kept a batch of interfaces on the grounds that "the SDK contract's scope does not cover the Worker/Verifier side", marking them
"to be confirmed" in `docs/nexus-sdk-contract-migration.md`. This round's Cortex contract gives the decision:

| WORK-9 handling | This round | Basis |
|---|---|---|
| `FetchPayload` kept (annotated "retirement to be confirmed") | Removed | Target-state baseline |
| `SubmitOutputRef` kept (outside SDK contract scope) | Removed | Target-state baseline |
| `UploadTaskData` kept (outside scope) | Renamed to `UploadTaskResultData` | §2.1 |
| `RefreshTaskDataAuthorization` marked `deprecated`, removal date pending decision | Removed | Target-state baseline |
| `GetTaskDataMetadataResponse.download_authorization` marked `deprecated` | Removed | §2.3 |
| `FetchTaskDataRequest.authorization` marked `deprecated`, "still required in V1" | Removed | §2.2 |
| `SubmitOrder` / `FetchOutputRef` / `RefreshCredential` marked `deprecated`, pending decision | **Still to be confirmed** (only their `output_ref` fields removed) | Not on this contract's decision list |

Three items still await a member decision (the Cortex contract does not cover whether they stay): `SubmitOrder`,
`FetchOutputRef`, `RefreshCredential`. Note that `RefreshCredential` directly conflicts with the contract's "V1 does not issue, prepare or
refresh standalone download credentials"; it is recommended to decide them together.

---

### 8. Item-by-item handling of contract §8 "Not yet frozen or outside this document"

| # | Unfrozen item | Handling this round | What it blocks |
|---|---|---|---|
| 1 | `canonical(TaskOrder)` encoding and the final wire representation of `task_hash` | Partially settled | `task_hash` is now preimage field 4 of `SignedInferReceiptV1` (raw 32 bytes) and **participates** in the receipt digest recomputation; `SubmitInferReceiptRequest.task_hash` is downgraded to a copy, and any mismatch with the one inside the receipt is rejected outright. `canonical(TaskOrder)` itself is still not frozen, so it is still not compared with the on-chain `task_hash` |
| 2 | Worker/Verifier role-signature envelope and SignBytes structure | Provisional assumption | Reuses `TaskDataRequestAuthV1` to carry the role signature, domains `TRUEOPEN_SUBMIT_INFER_RECEIPT_V1` / `..._VERIFY_COMMIT_V1` / `..._VERIFY_RESULT_V1`, 4-byte length-prefixed frame. Signature bytes will change once frozen (breaking) |
| 3 | Proto name, field numbers and canonical encoding of the Builder storage confirmation | Provisional assumption | The field set of `BuilderStorageConfirmationV1` is settled per the §5 semantic scope; encoding uses a provisional frame in the `TRUEOPEN_BUILDER_STORAGE_CONFIRMATION_V1` domain; the material digest will change once frozen, and confirmations stored on the Worker side must be re-fetched |
| 4 | `FetchTaskData` range anti-replay fields and the multi-evidence selector structure | Provisional assumption | Range binding elements implemented per the list in §2.2 (requester/Task/data_kind/range/validity/nonce + chain/builder); the evidence selector still uses the existing `EvidenceSelectorV1` (kind + artifact_id) |
| 5 | Verification Profile requirements on evidence types, counts and commitment form | Partially settled | The commitment **form** is frozen with Keeper §5.14: closed `EvidenceKind` + raw 32-byte `evidence_hash_or_root` + `uint64 encoded_size_bytes`; the list is strictly ascending by kind and unique (non-ascending/duplicates rejected outright, no silent reordering). Still unfrozen is "which kinds and what count bounds the locked profile requires", so locally only a non-empty list is required and the kind set is not asserted (registered as CONTRACT-GAP in node#89). `UploadTaskResultDataHeader.evidence_type` remains a free string. `VerifyMetricSummaryV1` unchanged |
| 6 | Weighted selection algorithm inside CandidatePoolSnapshot | Skipped | The existing handraise aggregation and selection logic is untouched; the boundaries frozen by the contract (unified snapshot, role filtering, union bitmap, selection after window close) are in §9 check items 3/4 |
| 7 | Settlement submission payload, challenge evidence and penalty algorithm | Skipped | `SettleTx` assembly untouched; `SETTLE` exists only as a BusEnvelope stage value |
| 8 | Final publishing policy for `OUTPUT_AVAILABLE` | Skipped (implemented as an optional hint) | Subject and Kind are settled, but it is not a condition for any state advance; payload trimmed to the §4.4 field set |
| 9 | Final renaming of wire Type URLs such as `MsgAssign` / `MsgOpenVerify` / `MsgSettle` | Skipped | Chain-side Type URLs untouched (changing them requires Node to move in sync); this is also one root cause of the §9 check item 2 non-compliance |

**§4-A notes (implementation assumptions introduced this round; members should be aware)**:

1. ~~The contract gave no definition of the `FRAME_V1` byte layout~~ (corrected by issue #37): the layout has long been frozen in
   Keeper Interface Contract §1.2 and "03 Model Registration On-Chain Structure and Manifest";
   the implementation was changed to `ascii("TRUEOPEN_FRAME_V1") || u32be(len(domain)) || domain ||
   u64be(len(payload)) || payload`.
2. ~~The contract gave no implementation details for `trueopen-cjson-v1`~~ (corrected by issue #37): "Interface & Topic Catalogue" §5.2
   already specifies "integers as decimal JSON integers, bytes/signatures as lowercase even-length `0x` hex,
   keys sorted ascending by UTF-8 bytes", sharing its origin with keeper `canonical_json_v1` (HTML escaping off;
   null / duplicate keys / non-canonical integers rejected). Both the implementation and the wire body encoding are aligned,
   with spec vectors locked in `internal/msgbus/envelope_v1_spec_test.go`.
3. ~~The contract gave no field table for `VerifyMetricSummaryV1` (only "typed")~~ (corrected by the initial relay implementation):
   replaced by `ResultMetricSummaryV1`, isomorphic to the on-chain `MetricSummaryV1`; see §4-B.
4. The contract gives no concrete value for `local_replay_safety_margin`; it is a caller parameter (`SafetyMarginMS`).

**§4-B (initial Builder relay of verify commit / result)**

**Conclusion: the Builder provides relay for the verify stage; direct submission by the Verifier is the fallback.** `SubmitVerifyCommit` /
`SubmitVerifyResult` validate the request and the role signature, then relay the on-chain frozen `VerifyCommitV1` /
`ResultReceiptV1` unchanged in a batch message; the response `relay_accepted=true` only means broadcast,
not accepted on-chain. A Verifier that has not observed acceptance before the deadline still submits the same message directly per contract §2.5 / §2.6
(`SelfRescueV1.RELAY_UNAVAILABLE`). `MsgSubmitFullResultReveal` is only accepted on-chain with the
Verifier itself as submitter; it is not relayed.

**Why batch messages.** The submitter of a single on-chain `MsgSubmitVerifyCommit` / `MsgSubmitVerifyResult`
must be the Verifier's own current service address (`requireVerificationSubmitter`, the direct-submission
path); Builder relay can only go through `MsgBatchSubmitVerifyCommit` / `MsgBatchSubmitVerifyResult`,
whose outer signer must be the selected Builder's current service address (`authorizeOpenTaskBuilder`).
The previous NATS `VERIFY_RESULT` path used single messages with a Builder signature, which the chain would always reject; this round switches it to batch as well.
The initial implementation sends one per message, as soon as received, with no batching.

**Prerequisite: the Builder's transaction signing address = the current service address registered on-chain.** Nexus signs
transactions with the account key; when `identity.service_keystore_file` is not configured the account key and the service key are the same key (startup log
"builder account and service signatures share one key"), and relay passes. When the two keys are separate, relay is rejected by the chain
and transaction signing must first be switched to the service key.

**Request shape (Cortex-facing, breaking).** The request-level `verify_round` / `verifier_operator_address` /
`commit_hash` / `commit_key` / `metric_root` / `metric_summary` / ... are all removed (field numbers
reserved), replaced by `signed_commit: SignedVerifyCommitV1` / `signed_receipt: SignedResultReceiptV1`,
mirroring `task.v1.VerifyCommitV1` / `ResultReceiptV1` field by field (bytes as lowercase hex).
`metric_summary` is replaced by `ResultMetricSummaryV1`, isomorphic to the on-chain `MetricSummaryV1` (10 fp_1e6
fields, 7 and 8 optional). `service_authorization_nonce` and `expiry_height` are chosen by the Verifier itself and
enter the signature preimage; `commit_key` is recomputed by the Keeper and is not a caller field.

**Request envelope signature.** `request_auth.signature` is signed with the Verifier's current service key over
`sdkauth.BodyPreimage`, with domains `TRUEOPEN_SUBMIT_VERIFY_COMMIT_V2` /
`TRUEOPEN_SUBMIT_VERIFY_RESULT_V2` respectively, covering session_id and all fields of the body (optional fields encoded with a one-bit
"present" marker plus the value); see `verifyCommitSignBytes` /
`verifyResultSignBytes` in `internal/ingress/workerverifier.go`. The old V1 domains are incompatible with the old field set.

**Response and error codes.** `relay_accepted` / `idempotent` / `tx_hash` (result additionally carries `material_digest`
= sha256 of the deterministic proto encoding, the same value as on the JetStream path). `InvalidArgument`: wrong shape, rejected by
an on-chain final decision, a second commit from the same Verifier with different content; `PermissionDenied`: not the selected
Verifier for this task; `FailedPrecondition`: task not in the verification stage; `NotFound`: this Builder does not have the task;
`Unavailable`: chain temporarily unreachable; retry or fall back to direct submission.

**Not yet done (follow-ups).** Inclusion confirmation and retry: this round's "acceptance" stops at CheckTx passing; a message that passes CheckTx but is
rejected at inclusion is recorded locally yet absent on-chain, relying on direct submission by the Verifier as fallback; the clean solution is to consume the `COMMIT_ACCEPTED` /
`RESULT_ACCEPTED` events for reconciliation. Batching: combine commits from multiple Verifiers into one batch.

Before that, `internal/coordinator/submitter.go` deliberately does **not** open submission points for these three Msgs:
a stub submission point that builds the Msg but cannot fill in a valid signature preimage is worse than a deterministic rejection.

**`MsgReportDataUnavailable` is a different matter: the contract explicitly forbids relaying it.**
`proto/task/v1/msg_verification.proto` states that this message has no relay path -- the Cosmos Tx
signer must be the current service address of this round's selected Verifier operator, and no second
detached signature is accepted. Nexus is a Builder and can never satisfy this; `ProtocolEventCodeV1` also has no
data-unavailable event code, so there is not even a basis for inclusion confirmation. Therefore
the `TypeURLMsgReportDataUnavailable` constant in `internal/chaincli/txbuild.go` has been removed
(a comment explains why); it was previously a declaration that could be misread as "relay point to be added".

**`MsgSweepDeadline` is implemented.** It is not a relay: §9.6a defines it as BOUNDED_RUNNER; any
account can submit it, the runner pays its own gas, and the signer is Nexus's own Cosmos account. The submission point is
`Submitter.SubmitSweepDeadline`; inclusion confirmation goes through `DEADLINE_SWEPT` (event code 20) ->
`SweepDeadlineAccepted{DeadlineKind, TransitionCode}` -> Query reconciliation. Off by default
(`chain.deadline_sweep.enabled`), because "who acts as the public runner" is an operational choice rather than a protocol
obligation; when enabled it only sweeps verify-stage deadlines on tasks this Builder is tracking for which the chain itself has given a height.

Returning `relay_accepted=true` would violate the mandatory rule of contract §7 (an RPC success must not be described as an accepted obligation / landed on-chain).

**§4-C notes (query shape and error codes for the current service key, gh #22)**:

The query shape is fixed per the frozen contract: `QueryCurrentServiceKeyRequest.participant_type` is the
`hub.v1.ParticipantType` **enum** (`PARTICIPANT_TYPE_CORTEX = 1` /
`PARTICIPANT_TYPE_BUILDER = 2`, `common.proto:19-24`), and the response is
`CurrentServiceKeyViewV1` (`service_pubkey` as bytes, `service_authorization_nonce`,
and a status that is a oneof selected by `participant_type`). enum and string are different wire types
(varint vs length-delimited); sending a string means the request cannot be sent and the response cannot be decoded.

Whether the same Cortex Node takes the Worker or the Verifier role, its current service key is registered under the
`PARTICIPANT_TYPE_CORTEX` domain -- `WORKER` / `VERIFIER` are `sender_role`, not the query domain.
The `"CORTEX_NODE"` currently sent by Cortex's `internal/chainclient/service_descriptor.go` has no corresponding value in that
enum and **must be switched in the same batch as this repository** (Node / Nexus / Cortex, three parties).

Accompanying Cortex-facing error code change: on the role-signature path, "on-chain current service key lookup unavailable"
(chain query failing, and being unable to construct a valid enum from the participant type domain) previously shared
`Unauthenticated / SDK_AUTH_INVALID_SIGNATURE` with "invalid signature"; it is now
`Unavailable / NEXUS_INGRESS_SERVICE_KEY_AUTHORITY_UNAVAILABLE`, consistent with the taskdata path's
`NEXUS_DATA_AUTHORITY_UNAVAILABLE -> Unavailable`. Affects `SubmitInferReceipt` /
`SubmitVerifyCommit` / `SubmitVerifyResult` / `FetchOutputRef`: Cortex should treat `Unavailable`
as a retryable chain lookup fault and only treat `Unauthenticated` as the key or signature genuinely being wrong. Merging them into one code would make
chain-side faults get investigated as authentication problems.

No historical-key fallback: a failed chain query still fails closed, and the old key becomes invalid immediately after rotation.

---

### 9. Item-by-item check of the 11 items in contract §9 "Implementation alignment check"

| # | Check item | Result | Basis |
|---|---|---|---|
| 1 | `OutputRef`, `output_cid`, `canonical_output_package_hash`, `delivery_output_hash` no longer appear | **Partially compliant** | `output_cid` / `canonical_output_package_hash` / `delivery_output_hash` as identifiers have been cleared from `proto/nexus/v1` and `internal/**` (non-test), leaving only explanatory comments. `OutputRef` still exists in three places: (1) the pending `FetchOutputRef` RPC and its request/response (the issue explicitly forbids removing it in passing); (2) the event code wire value `OUTPUT_REF_RECEIVED` (frozen by SDK contract §3.8; conflict pending decision); (3) `reserved` declarations in `proto/task/v1/{msg_assignment,open_verify}.proto` (mirror of the Node baseline, and already reserved) |
| 2 | The Open Verify proposal does not carry output/evidence commitments again; it only references the accepted `infer_receipt_hash` | **Compliant (structurally)** | The receipt string copies in `chaincli.OpenVerifyTx` (commit hash / output hash / roots / token_count / work_unit / service signature) are all removed, leaving only the `InferReceipt *taskv1.InferReceiptV1` body; `taskfsm` fills it, and `defaultSubmitter.SubmitOpenVerify` assembles `MsgSubmitInferReceipt` per §10.3. The receipt body must still be carried in full (the Keeper recomputes `infer_receipt_signing_digest`), which is exactly what §5.14 requires, not duplicate carriage |
| 3 | A single Builder proposal only needs to add at least 1 valid handraise; the candidate total is not checked per proposal | **Not applicable (unchanged this round)** | The existing implementation uses the `handraiseMin` threshold to decide when to submit a proposal; this falls within the §8.6 unfrozen selection-algorithm boundary, untouched this round, and no new total-count check was introduced |
| 4 | Final Worker/Verifier selection happens only after the window closes | **Compliant** | Selection still comes from on-chain events (`AssignmentFinalized` / `OpenVerifyAccepted`); handraise messages only aggregate and do not decide the winner. The target-state definitions of `WORKER_ASSIGNMENT_NOTIFY` / `VERIFIER_ASSIGNMENT_NOTIFY` also state "may only be sent after Finalized" |
| 5 | Use `selected Worker`, `selected Verifier`, `Task Builders`; do not use "official Verifier" or "the Builder that returns OutputRef" | **Partially compliant** | Comments and new code changed this round uniformly use selected Worker/Verifier; `internal/coordinator` still has legacy "formal Verifier" / "winner" wording (not rewritten everywhere), a wording debt |
| 6 | Verification covers all committed generated token IDs; no checkpoint sampling, Worker reveal, `sample_values` or sample seed | **Non-compliant (known gap)** | The `SubmitVerifyResult` API surface is validated under the full-coverage rule (`token_scope` must be `ALL_GENERATED_OUTPUT_TOKENS`, and `sample_values`-type fields are rejected). But the coordinator's settlement decision is still based on the number of consistent `sample_values` (`consistentVerifyGroup` / `minConsistentVerifyResults`), and `SampleReadyNotify` and `WorkerReveal` remain. The chain still has `WorkerRevealTx` / `FullResultRevealState` too; a four-party synchronized change |
| 7 | VerifyResult uses metric root, typed summary, aggregate proof digest and commit/reveal binding; carries no verdict | **Compliant (API surface)** | The `SubmitVerifyResultRequest` field set is settled per §2.6; tests assert the absence of `verdict` / `sample_values` / `sample_seed` / `evidence_ref`. For the on-chain relay side see check item 6 and §4-B |
| 8 | InferReceipt relay does not wait for the output/evidence upload; direct submission does not end the upload obligation | **Compliant** | `SubmitInferReceipt` and `UploadTaskResultData` are fully independent: the receipt path checks no upload state, and `OnInferReceipt` does not touch taskdata; the response field is named `relay_accepted` and the proto comment states it means neither landed on-chain nor stored |
| 9 | 2/3 Builder storage is a normal redundancy target, not a Keeper gate, and no single Builder is required to aggregate other Builders' confirmations | **Compliant** | The storage confirmation is issued only by the current Builder with its own current service key; `SignStorageConfirmation` reads no cross-Builder state; the proto comment states "a single RPC represents only the current Builder" |
| 10 | `VERIFY_RESULT` belongs to the `OPEN_VERIFY` coarse group; Settlement is not extended into a new Verification stage | **Compliant** | `subjectSpecsV1` sets the stage of `VERIFY_RESULT` to `OPEN_VERIFY`, `StageV1` has only three values, and verification step 5 rejects envelopes whose stage does not match the Kind group (covered by tests) |
| 11 | Nexus ack / NATS delivery / IngressAPI success responses / Builder storage confirmations must not be described as on-chain accepted (§7 mandatory rule) | **Compliant** | The response fields of the three added submission methods are all named `relay_accepted`, and both proto and implementation comments state the boundary: broadcast only, not on-chain accepted (§4-B) |

---

### 10. H_FIELDS_V1 reshape: Cortex-facing breaking-change notice

Upstream TrueOpen/node made four decisions in `d1dbf81` (node#89 / #90 / #91 / #95),
and Nexus accordingly switched the whole receipt path to the frozen definition. **TrueOpen/cortex must change its signing in the same batch**,
otherwise receipts signed by Workers will be rejected by Nexus (and by the Keeper too).

#### 10.1 The signature preimage switches to H_FIELDS_V1 typed framing

Old definition (removed, **no alias kept**): `domainHash("TRUEOPEN_INFER_RECEIPT_V1", 11 string fields)`,
uint64 written as decimal text, Hash32 written as hex text, and covering 6 fields since removed from the wire.

New definition (Keeper Interface Contract §5.14 / §1.2, implemented in `internal/nodecontract.InferReceiptSigningDigest`):

```
infer_receipt_hash = infer_receipt_signing_digest =
  H_FIELDS_V1("TRUEOPEN_INFER_RECEIPT_V1",
    schema_version, chain_id, task_id, task_hash, worker_operator_address,
    service_authorization_nonce, generation_params_digest, output_hash,
    output_size_bytes, evidence_commitments_hash, expiry_height)

preimage = u64_be(len(domain)) || domain || for each field: u64_be(len(field)) || field
digest   = SHA256(preimage)
```

Field encoding: `uint32`/`uint64` big-endian fixed width; `bytes` raw bytes (Hash32 is exactly 32 bytes, **not hex text**);
`string` strict UTF-8 bytes (no trimming, no case folding); `enum` uint32 big-endian;
`address` **address codec bytes** (the 20 bytes decoded from bech32, **not bech32 text**; decision 24 / node#95).

The 10th preimage field is not a wire field:

```
evidence_commitments_hash =
  H_FIELDS_V1("TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1",
    uint32_be(count), frame(commitment[0]), ... frame(commitment[count-1]))
```

Three easy pitfalls (quoted from node#89): the domain is `TRUEOPEN_INFER_EVIDENCE_COMMITMENTS_V1`
(35 bytes), not `TRUEOPEN_EVIDENCE_COMMITMENTS_V1`; this preimage carries **neither chain_id
nor task_id** (the outer layer already binds the scope; binding again would be double binding); the digest of the empty list is
`393ca3fb29b409f454b6f870f972c4a8fdffbf9934eadd628ecfdf0f03789764`, **never 32 zero bytes**.

A single commitment is a nested `FieldFrameV1` (no domain prefix, ascending by field number), always 68 bytes:
`u64_be(4)||uint32_be(evidence_kind)` + `u64_be(32)||evidence_hash_or_root` +
`u64_be(8)||uint64_be(encoded_size_bytes)`.

The signature is still strict secp256k1 over this 32-byte digest (compact R||S, low-S),
byte-for-byte consistent with the behavior of Cosmos `secp256k1.PubKey.VerifySignature`.

The golden vectors are copied byte for byte from node `d1dbf81`'s `x/task/types/testdata/task_domains_v1.json`
into `internal/nodecontract/testdata/task_domains_v1.json` (sha256 `8778fad1…7ae5`);
the preimage / digest / bit-wise tamper / replay of all 9 vectors are aligned.

#### 10.2 Wire field changes

The field numbers of `nexus.v1.SignedInferReceiptV1` are renumbered to align with `task.v1.InferReceiptV1`:

| # | Field | Change |
|---|---|---|
| 1 | `schema_version` | **Added** (always 1 in V1, node#90; a wrong guess yields a digest the Keeper will never accept) |
| 2 | `chain_id` | **Added** (must equal this chain's chain_id, otherwise rejected) |
| 3 | `task_id` | Kept (canonical lowercase 64-hex Hash32) |
| 4 | `task_hash` | **Added** (enters the preimage; the request-level field of the same name is downgraded to a copy, mismatch rejected outright) |
| 5 | `worker_operator_address` | Kept (enters the preimage as address codec bytes) |
| 6 | `service_authorization_nonce` | **Added** (must be non-zero) |
| 7 | `generation_params_digest` | **Added** (canonical lowercase 64-hex Hash32) |
| 8 | `output_hash` | Kept |
| 9 | `output_size_bytes` | Kept |
| 10 | `required_evidence_commitments` | **Added** (moved into the receipt from request-level field 5: must be signed together with the receipt) |
| 11 | `expiry_height` | **Added** (must be non-zero) |
| 12 | `service_signature` | Kept |
| — | `infer_receipt_commit_hash` / `infer_receipt_hash` / `trace_commit_root` / `checkpoint_commit_root` / `batch_log_root` / `token_count` / `work_unit` | **Removed, no compatibility layer** |

Removing `infer_receipt_hash` from the wire is deliberate: §5.14 defines it as the same value as `infer_receipt_signing_digest`,
so there is no assertable copy -- Nexus and the Keeper each recompute it.
`SubmitInferReceiptResponse.infer_receipt_hash` still returns that recomputed value (as an acknowledgement only, not a consensus fact).

`work_unit` / `token_count` land in the `SETTLEMENT_BILL` leaf of decision 32
(`proto/task/v1/settlement.proto`) and no longer enter the receipt; K-BLOCK-16 is unresolved, and the chain still does not write that leaf.

`EvidenceCommitmentV1` switches to the closed shape. `EvidenceKind` is **redeclared** in `nexus.v1`
rather than importing `shared/v1/contract_base.proto`: this file is generated into the independent contract module `gen/trueopen`,
which may only depend on stdlib / connect / protobuf (`gen/trueopen/contract_guard_test.go`).
The numbering must match `shared.v1.EvidenceKind` entry by entry; changing a number changes the consensus digest.

#### 10.3 What the Cortex side needs to do

1. Rewrite the receipt digest derivation per §10.1 (or reuse the field definitions from `gen/trueopen` directly + the framing above).
2. Fill in the 4 new fields plus `task_hash` / `chain_id`; `schema_version = 1`.
3. Move `required_evidence_commitments` from request level into the receipt, strictly ascending by `evidence_kind` with unique kinds,
   and pass `evidence_hash_or_root` as raw 32 bytes (not hex text).
4. Self-check with node's golden vectors: the `infer_receipt_v1` digest should be
   `5cc54445a2c128729a5b4fbe86aa34af485d5e9f14ab1b56b5059f13787a3947`.

#### 10.4 Still open (outside this round's scope)

Node's keeper / query have not yet switched to `InferReceiptV1` (`d1dbf81` only redirected the preimage;
the handler rewrite belongs to Node's Task slice). Therefore:

- The on-chain `InferReceiptState` (`proto/task/v1/open_verify.proto`) is still the pre-freeze shape;
  `taskdata.receiptMatchesChain` compares only facts whose semantics are unchanged on both sides (worker / output_hash /
  service_signature) and **deliberately does not compare the hash value** -- the on-chain one is still computed from the old preimage,
  and comparing it would misclassify normal receipts as conflicts. Once Node has switched, this should compare digests directly.
- Real inclusion of `MsgSubmitInferReceipt` likewise depends on the Node-side handler being in place. This repository's gate goes as far as
  "the receipt digest and the Worker signature inside the signed tx can be recomputed and verified by the Keeper"
  (`internal/coordinator.TestInferReceiptReachesChainAsMsgSubmitInferReceipt`).
- `TraceCommitRoot` / `CheckpointCommitRoot` in `nodecontract.SettlementEvidenceInput`
  are replaced by a single `EvidenceCommitmentsHash`. The helper as a whole is still the pre-freeze shape (the settlement leaf
  encoding is not frozen, K-BLOCK-16 unresolved); this is only an equivalent substitution.

---

### 11. Verification

The real output of `make proto-lint`, `make proto`, `make build`, `make vet` and `make test` (root module + `gen/trueopen`
submodule) is pasted in the delivery comment of this issue. After `make proto`, `gen/` has no manual changes
(`gen/trueopen/nexus/v1/ingress.pb.go` and `nexusv1connect/ingress.connect.go` are buf-generated).
