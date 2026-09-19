## Nexus<->SDK Interface Contract Migration Mapping

Alignment baseline: "Nexus<->SDK Interface Contract" v0.1 (2026-08-14, `owner: nexus-engineering`, status "under review").
Alignment target: `service IngressAPI` in `proto/nexus/v1/ingress.proto`.
On conflict the contract prevails; contract §8 "Unfrozen Items" and §9 "Upstream Discrepancies Pending Clarification" are only recorded here, not implemented or adjudicated.

**The contract's scope is "the field-level contract of the Nexus IngressAPI toward the SDK (User-side service)".**
Therefore the absence of Worker / Verifier-side methods from the contract **is not grounds for deletion** -- this table lists them as a separate category,
strictly distinguished from "existing SDK methods superseded by the contract".

Before alignment `IngressAPI` had 15 RPCs; contract §3 has 9. The table below covers the destination of all 15 and the source of all 9.

### 1. RPC-level mapping

| Old RPC | New RPC | Change type | Basis | Breaking | Notes |
|---|---|---|---|---|---|
| `OpenTask` (client stream) | `OpenTask` (client stream) | Field change | §3.1 | No (field added) | Added `idempotency_key`; BodyDigest order not frozen (§8.1), unchanged |
| — | `ConfirmOpenTask` (unary) | Added | §3.2 | No (method added) | Skeleton: returns `Unimplemented`; field table awaits §8.2/§8.3 freeze |
| `GetTaskDataMetadata` | `GetTaskDataMetadata` | Field change | §3.3 | No (deprecated only) | The response's `download_authorization` contradicts "does not return read permissions"; marked deprecated |
| `DownloadTaskData` (server stream) | `FetchTaskData` (server stream) | Rename | §3.4 | **Yes** | Method name renamed together with `DownloadTaskDataRequest/Response` |
| `SubscribeOutput` (server stream) | `SubscribeOutput` (server stream) | Unchanged | §3.5 | No | RESERVED as a whole (§8.5); frame structure differences in the §3 table |
| `AckOutput` | `AckOutput` | Unchanged | §3.6 | No | RESERVED as a whole (§8.5); request field differences in the §3 table |
| `GetTaskStatus` | `GetTaskStatus` | Unchanged | §3.7 | No | `state` value differences in the §4 table |
| `GetTaskEvents` (server stream) | `GetTaskEvents` (server stream) | Unchanged | §3.8 | No | `event_code` value differences in the §4 table |
| `PrepareChallenge` | `PrepareChallenge` | Unchanged | §3.9 | No | Response field naming differences in the §3 table |
| `FetchPayload` | `FetchPayload` | Unchanged (outside contract scope) | Contract scope | No | Worker/Verifier side; `FetchTaskData` covers the same read need, retirement **to be confirmed** |
| `SubmitOutputRef` | `SubmitOutputRef` | Unchanged (outside contract scope) | Contract scope | No | Worker-side return path, not covered by the contract |
| `UploadTaskData` (client stream) | `UploadTaskData` (client stream) | Unchanged (outside contract scope) | Contract scope | No | Worker/Verifier-side upload of OUTPUT/EVIDENCE, not covered by the contract |
| `SubmitOrder` | None (taken over by `OpenTask`) | To be confirmed (marked deprecated) | §3.1 | **Yes** on deletion | The only SDK-side order entry is the client-stream `OpenTask`; the contract has no unary ordering |
| `FetchOutputRef` | None (taken over by `GetTaskDataMetadata` + `FetchTaskData`) | To be confirmed (marked deprecated) | §3.3 / §3.4 | **Yes** on deletion | The contract returns no locator and issues no retrieval credentials |
| `RefreshCredential` | None | To be confirmed (marked deprecated) | §3.3 / §3.4 | **Yes** on deletion | The `CredentialV1` retrieval-credential route is superseded by the contract as a whole |
| `RefreshTaskDataAuthorization` | None | To be confirmed (marked deprecated) | §3.4 | **Yes** on deletion | The contract states "V1 issues no separate download authorization; on-chain role is the permission" |

Full coverage of the sources of the contract's 9 RPCs: `OpenTask` <- same name; `ConfirmOpenTask` <- added;
`GetTaskDataMetadata` <- same name; `FetchTaskData` <- `DownloadTaskData`; `SubscribeOutput` <- same name;
`AckOutput` <- same name; `GetTaskStatus` <- same name; `GetTaskEvents` <- same name; `PrepareChallenge` <- same name.

### 2. Why no RPC is deleted in this round

`gen/trueopen` is an independent Go module (`github.com/TrueOpen/nexus/gen/trueopen`) that external consumers such as Cortex depend on directly.
Deleting an RPC or message would break their builds. The contract itself is "under review", and the four superseded methods touch
two complete implementation chains, retrieval credentials and download authorization (`internal/credential`, `internal/relay`,
authorization issuance in `internal/taskdata`). So this round only marks intent with `option deprecated = true`,
leaving the deletion timing to the team's decision. `TestSDKContractSurface` in `internal/ingress` guards this state:
the 9 contract methods must not be marked deprecated, and the 4 superseded methods must not lose their deprecated mark before deletion.

### 3. message / field-level mapping

| Old message.field | New message.field | Change type | Basis | Breaking | Notes |
|---|---|---|---|---|---|
| `OpenTaskHeader` (11 fields) | `OpenTaskHeader.idempotency_key = 12` | Added | §3.1 | No | The contract lists it as required; **server-side idempotent dedup not implemented**, currently only received, not validated (skeleton + TODO) |
| `OpenTaskHeader.order_envelope` + `signature_scheme` + `signature` | The contract's `signed_order` | Semantic change | §3.1 | No | The contract's SignedOrder = TaskOrder + scheme + user_signature; the three fields together are exactly that; noted in the proto comments |
| `OpenTaskResponse{task_id, accepted, reason, session_id, input_metadata}` | Contract observed shape `{session_id, task_id, accepted, reason}` | Unchanged | §3.1 | No | The implementation is a superset of the contract; `input_metadata` additionally returns the storage confirmation data |
| `DownloadTaskDataRequest` | `FetchTaskDataRequest` | Rename | §3.4 | **Yes** | Field numbers and names unchanged |
| `DownloadTaskDataResponse` | `FetchTaskDataResponse` | Rename | §3.4 | **Yes** | Same as above |
| `FetchTaskDataRequest.authorization` | (removed in target state) | To be confirmed (marked deprecated) | §3.4 | **Yes** on deletion | "V1 issues no separate download authorization"; still required in V1 to avoid a half-applied change |
| `GetTaskDataMetadataResponse.download_authorization` | (removed in target state) | To be confirmed (marked deprecated) | §3.3 | **Yes** on deletion | The contract states this method returns no read permissions |
| `FetchTaskDataRequest.range` (`SignedTaskDataRangeV1`) | The contract's `authenticated recipient + range` | Unchanged | §3.4 / §8.6 | No | range already binds recipient/nonce/expiry/signature; exact wire structure not frozen, untouched |
| `TaskDataMetadataV1` | Contract §3.3 response set | Unchanged | §3.3 | No | Size / semantic hash / storage state / retention boundary / `signed_infer_receipt` / `accepted_receipt_hash` match item by item |
| `AckOutputRequest.output_id` | The contract's `stream_id` + `output_hash` | **To be confirmed** | §3.6 | **Yes** if changed | The contract's frozen request fields and BodyDigest both require `stream_id, output_hash`; alignment presupposes `SubscribeOutput` is first framed per §3.5, yet that pair of RPCs is RESERVED as a whole (§8.5) |
| `SubscribeOutputResponse{output_id, output_text, output_hash, created_at, expires_at}` | Contract frame `{stream_id, server_issued_stream_epoch, seq, offset, chunk_hash}` + FIN | **To be confirmed** | §3.5 | **Yes** if changed | Currently a single plaintext frame of the whole segment; whether `server_issued_stream_epoch` enters the frame is an unadjudicated discrepancy (§9.2) |
| `PrepareChallengeResponse.challenge_close_height` (uint64) | The contract's `challenge_close` (int64) | **To be confirmed** | §3.9 / §8.7 | **Yes** if changed | Unit (block height vs Unix ms) not unified; rename and type change wait for the decision together |
| `PrepareChallengeRequest.challenge_kind` (string) | Same | Unchanged | §3.9 | No | The contract requires V1 to enable only `VerdictFraudProof`/`ProtocolFaultProof`; **the server does no value allowlist check** (gap) |
| `GetTaskStatusResponse.stage` / `set_id` / `updated_at` | Same | Unchanged | §3.7 | No | The contract recognizes them as proto-reserved, not populated by the implementation; noted in the proto comments |
| `SDKRequestEnvelopeV1` (12 fields) | Same | Unchanged | §2 | No | Field set, SignBytes order and Replay key match the contract item by item; see the next section |
| `SubmitOrderRequest` / `SubmitOrderResponse` | None | To be confirmed | §3.1 | **Yes** on deletion | Goes with `SubmitOrder` |
| `FetchOutputRefRequest` / `FetchOutputRefResponse` / `OutputRef` | None | To be confirmed | §3.3 / §3.4 | **Yes** on deletion | `OutputRef` is also referenced by the `RefreshCredential` response |
| `RefreshCredentialRequest` / `RefreshCredentialResponse` / `CredentialV1` / `AccessLevel` | None | To be confirmed | §3.3 / §3.4 | **Yes** on deletion | The retrieval-credential family retires as a whole; `CredentialV1` is also referenced by `FetchPayloadResponse` (Worker side), so deletion requires decoupling first |
| `RefreshTaskDataAuthorizationRequest/Response` / `TaskDataAuthorizationV1` | None | To be confirmed | §3.4 | **Yes** on deletion | `TaskDataAuthorizationV1` is also referenced by `GetTaskDataMetadataResponse` and `FetchTaskDataRequest` |

`SDKRequestEnvelopeV1` item-by-item check (contract §2): all 11 contract fields + `signer_pubkey` exist with matching semantics;
the order in `internal/sdkauth.SignBytes`, `TRUEOPEN_SDK_REQUEST_V1, chain_id, method, endpoint, session_id,
task_id, request_nonce, i64be(expiry_height_or_time), body_digest`, matches the contract word for word;
the Replay key `request_domain \x00 chain_id \x00 signer_address \x00 hex(request_nonce)` matches.
Enforcement matches too: `SubscribeOutput`/`AckOutput` always require the envelope, `GetTaskStatus` does not check it,
and the remaining methods are governed by `require_sdk_envelope`. The `task_id` derivation (`internal/types.DeriveTaskID`) matches contract §1's
`hex(sha256("TRUEOPEN_TASK_ID_V1|" + trim(session_id) + "|" + decimal(order_sequence)))`, including the trim semantics.

### 4. Enum mapping

`GetTaskStatus.state` (contract §3.7) -- only the second item differs:

| Contract value | Implementation value (`internal/types.TaskState`) | Change type | Breaking |
|---|---|---|---|
| `PENDING` | `PENDING` | Unchanged | No |
| `WORKER_ASSIGNED` | `ASSIGNED` | **To be confirmed** | Yes if changed (wire-visible string) |
| `VERIFYING` | `VERIFYING` | Unchanged | No |
| `SETTLED` | `SETTLED` | Unchanged | No |
| `CLOSED` | `CLOSED` | Unchanged | No |
| `FAILED` | `FAILED` | Unchanged | No |

Reason for leaving it unchanged: contract §9.6 lists the phase->state mapping and its enum values as an unadjudicated upstream discrepancy
(Catalogue §8.1 and SDK Detailed Design §2.7 disagree). Changing `ASSIGNED`->`WORKER_ASSIGNED` would be adjudicating that item.
If the team decides to adopt the contract values, the change point is one line in `internal/types.TaskState.String()` + related tests.

`GetTaskEvents.event_code` (contract §3.8 full set of 10 items vs 15 in the implementation, `internal/coordinator/events.go`):

| Implementation event_code | Contract event_code | Change type | Breaking | Notes |
|---|---|---|---|---|
| `ORDER_RECEIVED` | `ORDER_RECEIVED` | Unchanged | No | |
| `ASSIGN_ACCEPTED` | `WORKER_HANDRAISES_ACCEPTED` | **To be confirmed** (rename) | Yes if changed | Semantic alignment: the consumption point in contract §4 = the first valid `MsgSubmitWorkerHandraises` accepted by the Keeper |
| `ASSIGNMENT_FINALIZED` | `WORKER_ASSIGNMENT_FINALIZED` | **To be confirmed** (rename) | Yes if changed | |
| `OUTPUT_REF_RECEIVED` | `OUTPUT_REF_RECEIVED` | Unchanged | No | |
| `OPEN_VERIFY_ACCEPTED` | `VERIFIER_ASSIGNMENT_FINALIZED` | **To be confirmed** (rename) | Yes if changed | The implementation semantics are "formal Verifiers fixed, seed not yet fixed"; equivalence with the contract name needs confirmation |
| `FULL_RESULT_REVEAL_ACCEPTED` | `FULL_RESULT_REVEAL_ACCEPTED` | Unchanged | No | |
| `SETTLE_ACCEPTED` | `TASK_SETTLED` | **To be confirmed** (rename) | Yes if changed | |
| `SWEEP_OBSERVED` | `SWEEP_OBSERVED` | Unchanged | No | |
| `TASK_CLOSED` | `TASK_CLOSED` | Unchanged | No | |
| `TASK_RECOVERED` | `TASK_RECOVERED` | Unchanged | No | |
| `ASSIGN_TIMEOUT` | Not in the contract set | **To be confirmed** (contract gap) | Yes on deletion | Not on chain before the order deadline |
| `ASSIGN_REJECTED` | Not in the contract set | **To be confirmed** (contract gap) | Yes on deletion | DeliverTx rejected before the task was created |
| `SAMPLE_READY` | Not in the contract set | **To be confirmed** (contract gap) | Yes on deletion | Sampling seed ready; a fine-grained phase of the same name in `TaskPhase` |
| `WORKER_REVEAL_ACCEPTED` | Not in the contract set | **To be confirmed** (contract gap) | Yes on deletion | Worker reveal receipt on chain |
| `TASK_FAILED` | Not in the contract set | **To be confirmed** (contract gap) | Yes on deletion | None of the contract's 10 items is a failure event, yet `state` has `FAILED`; cutting straight to the 10 items would leave the SDK without failure notifications |

When the team decides, it is recommended to handle "rename" and "contract gap" separately: the former is pure naming, the latter first requires deciding whether the contract's 10 items are
truly the full set or omit failure events. This round changes no event codes.

`DataKind` (contract §3.3): `INPUT` / `OUTPUT` / `EVIDENCE` map one-to-one to `DATA_KIND_INPUT/OUTPUT/EVIDENCE`
(plus the proto-conventional `DATA_KIND_UNSPECIFIED = 0`), unchanged.

### 5. BodyDigest field order check

The contract freezes only 4 (§8.1); each checked against the implementation (`internal/ingress/service.go`):

| Method | Contract frozen order | Implementation | Conclusion |
|---|---|---|---|
| `SubscribeOutput` | `session_id, task_id` | Same | Match |
| `AckOutput` | `session_id, task_id, stream_id, output_hash` | `session_id, task_id, output_id` | **Mismatch**, see the §3 table |
| `GetTaskEvents` | `session_id, task_id, from_cursor` | Same | Match |
| `PrepareChallenge` | `session_id, task_id, challenge_kind, local_evidence_digest` | Same | Match |

The unfrozen ones (`OpenTask` / `ConfirmOpenTask` / `GetTaskDataMetadata` / `FetchTaskData`) keep the current implementation and
are untouched this round -- in particular, the `OpenTask` digest already has SDK-side signers, so changing the order would change the signing scheme.

### 6. Error code check (contract §7)

| Scenario | Contract Code / stable text | Implementation | Conclusion |
|---|---|---|---|
| Missing field / malformed | InvalidArgument / `NEXUS_INGRESS_MALFORMED` | Most paths match; legacy paths such as `SubmitOrder`, `FetchPayload` return bare text (e.g. `empty payload_ref`) | Partial mismatch (legacy paths, handled together with their retirement) |
| SDK signature error | Unauthenticated / `SDK_AUTH_INVALID_SIGNATURE` | Match | Match |
| SDK expired | DeadlineExceeded / `SDK_AUTH_EXPIRED` | Match | Match |
| SDK nonce replay | Unauthenticated / `SDK_AUTH_REPLAY` | Match | Match |
| task does not exist | NotFound / `task not found` | `types.ErrTaskNotFound = "task not found"` -> NotFound | Match |
| data does not exist | NotFound / `DATA_NOT_FOUND` | NotFound / `NEXUS_DATA_NOT_FOUND` | **Text mismatch** (to be confirmed) |
| Past retention period | FailedPrecondition / `DATA_EXPIRED` | **DeadlineExceeded** / `NEXUS_DATA_EXPIRED` | **Both Code and text mismatch** (to be confirmed) |
| Requester signature invalid | Unauthenticated / `DATA_ACCESS_INVALID_SIGNATURE` | PermissionDenied / `NEXUS_DATA_UNAUTHORIZED` | **Mismatch** (to be confirmed) |
| Requester not authorized | PermissionDenied / `DATA_ACCESS_DENIED` | PermissionDenied / `NEXUS_DATA_UNAUTHORIZED` | Code matches, text mismatch (to be confirmed) |
| Internal error | Internal / cause chain | Match | Match |

This round does not change error texts, for two reasons:

1. `DATA_*` vs the implementation's `NEXUS_DATA_*` is a naming-convention conflict, while the other rows of the same contract table use the `NEXUS_INGRESS_*` prefix
   -- which prefix to unify on is a convention the team must set, not an implementation bug.
2. Changing "past retention period" to FailedPrecondition presupposes splitting `taskdata.ErrExpired` into two error values, "data expired" and
   "request expired": the same value is currently also used for the envelope expiry check in `OpenTask`, and the contract requires
   SDK expiry to return DeadlineExceeded. Changing the mapping directly would skew that case too.

`NEXUS_INGRESS_RATE_LIMITED` / `NEXUS_INGRESS_DUPLICATE_SUBMIT` / `DATA_UNAVAILABLE` in the footnote of contract §7
have no Connect code mapping (Catalogue §12.3 gap); the implementation has none either, and the gap remains.

### 7. Handling of contract §8 "Unfrozen Items"

| # | Unfrozen item | Handling this round |
|---|---|---|
| 1 | Exact BodyDigest order of `OpenTask`/`ConfirmOpenTask`/`GetTaskDataMetadata`/`FetchTaskData` | Skipped. Keep the current implementation; the new `idempotency_key` is **not** merged into the `OpenTask` digest, to be decided after freezing |
| 2 | `ConfirmOpenTask` request/response field table | Blocked. Only the composite key frozen in §1 + `request_envelope` are landed; confirmation list fields (from 13) left empty, handler returns `Unimplemented` |
| 3 | proto name / field numbers / encoding order of the Builder storage confirmation | Blocks #2. Without it the confirmation list of `ConfirmOpenTask` cannot be defined |
| 4 | `task_hash` domain / field set / canonical encoding / algorithm / wire | Skipped. This round does not touch `TaskOrder`/`task_hash`-related structures |
| 5 | `SubscribeOutput`/`AckOutput` RESERVED as a whole | Skipped. Accordingly the wire of these two RPCs is unchanged; only the differences in the §3 table are recorded |
| 6 | `FetchTaskData` range request wire structure; evidence selector structure | Skipped. `SignedTaskDataRangeV1` and `EvidenceSelectorV1` kept as-is; only the method rename |
| 7 | Unit of `PrepareChallenge.challenge_close` (height vs Unix ms) | Blocks the field rename. `challenge_close_height` (uint64) unchanged, noted in comments |
| 8 | Unification of the deadline field family (`deadline_policy`/`deadline`/`deadline_height`/`infer_deadline_height`) | Skipped. This round does not touch deadline fields |

### 8. Handling of contract §9 "Upstream Discrepancies Pending Clarification"

| # | Discrepancy | Handling this round |
|---|---|---|
| 1 | Whether the envelope signature covers `signer_address` | Skipped. The implementation follows Catalogue §4.3 and does **not** cover it, checking `bech32(signer_pubkey) == signer_address` instead; written into the proto comments. If the decision is "cover", `internal/sdkauth.SignBytes` must change, and all SDK signing schemes change in sync |
| 2 | Whether the `SubscribeOutput` frame contains `server_issued_stream_epoch` | Blocks the framing rework of `SubscribeOutputResponse` in the §3 table |
| 3 | The TaskOrder "generation parameters" field family | Not involved. `TaskOrder` is not in `ingress.proto` (carried via `order_envelope`) |
| 4 | Relationship between `input_size_hint` (TaskOrder) and `input_size_bytes` (RPC/on-chain) | Skipped. `OpenTaskHeader.input_size_bytes` keeps the existing check "equals the actual byte count of the full input"; whether the two are equal cannot be determined |
| 5 | The RESERVED output relay is written as the default retrieval path in the SDK Detailed Design | Skipped, but executed per the contract's RESERVED positioning: `SubscribeOutput` is neither treated as the default delivery path nor deleted |
| 6 | phase->state mapping | Blocks the `ASSIGNED` -> `WORKER_ASSIGNED` rename in the §4 table |

### 9. Breaking changes for `gen/trueopen` consumers this round (itemized)

The contract module `github.com/TrueOpen/nexus/gen/trueopen` has exactly the following breaking changes; consumers such as Cortex must update in sync when upgrading:

1. `IngressAPIClient.DownloadTaskData` -> `IngressAPIClient.FetchTaskData`
2. `IngressAPIHandler.DownloadTaskData` -> `IngressAPIHandler.FetchTaskData`
3. `nexusv1connect.IngressAPIDownloadTaskDataProcedure` -> `IngressAPIFetchTaskDataProcedure`
   (the procedure path changes from `/nexus.v1.IngressAPI/DownloadTaskData` to `.../FetchTaskData`,
   **wire-level break**: an old client calling the new server gets 404/Unimplemented)
4. `nexusv1.DownloadTaskDataRequest` -> `nexusv1.FetchTaskDataRequest`
5. `nexusv1.DownloadTaskDataResponse` -> `nexusv1.FetchTaskDataResponse`

Non-breaking but visible changes: the new `ConfirmOpenTask` method and `ConfirmOpenTaskRequest/Response`;
the new `OpenTaskHeader.idempotency_key` (field number 12); the four existing SDK methods and two authorization fields carry
`// Deprecated:` comments (compilation unaffected).

Field numbers, `DataKind` values and the `SDKRequestEnvelopeV1` structure are all unchanged.

### 10. What actually changed this round

- `proto/nexus/v1/ingress.proto`: `DownloadTaskData` -> `FetchTaskData` (including request/response messages);
  added `ConfirmOpenTask` + request/response; added `OpenTaskHeader.idempotency_key = 12`;
  4 superseded SDK methods and 2 authorization fields marked `deprecated`; service reordered by contract section, with comments completing the
  frozen sets (6 state items, 10 event_code items), BodyDigest and unfrozen items.
- `gen/`: regenerated with `make proto`, not hand-edited.
- `internal/ingress`: `DownloadTaskData` handler renamed to `FetchTaskData`; added the `ConfirmOpenTask`
  skeleton (returns `Unimplemented`); the task-data procedure allowlist in `server.go` follows the rename.
- `internal/taskdata`: `MethodDownload` (`"DownloadTaskData"`) -> `MethodFetch` (`"FetchTaskData"`).
  This constant takes part in no actual signing path (data fetching uses the range signature in the `TRUEOPEN_TASK_DATA_RANGE_V1` domain), so the rename does not affect already-signed bytes.
- Tests: added `TestSDKContractSurface` (existence and streaming shape of the 9 contract methods + deprecated status of the 4
  superseded methods), `TestConfirmOpenTaskIsUnimplementedUntilContractFreeze`,
  and a field-number assertion for `OpenTaskHeader.idempotency_key`.

### 11. Remaining skeletons and TODOs (not completed items)

- `ConfirmOpenTask`: only the method and composite key; no confirmation list, no server-side validation, returns `Unimplemented`. Blocked on §8.2/§8.3.
- `OpenTaskHeader.idempotency_key`: the field is on the wire, but **the server does no idempotent dedup** and does not enforce it as required
  (enforcing would break existing SDK clients). The contract §3.1 requirement "same key + same `input_hash` returns the same result,
  same key + different `input_hash` is rejected" is not yet implemented.
- Authorization tokens for `FetchTaskData` / `GetTaskDataMetadata`: the contract §3.4 target state is removal; currently still required.
  The permission decision itself is already "on-chain role is the permission" (`internal/taskdata.rolePermissions.canDownload`:
  selected Worker -> INPUT, selected Verifier -> all, original User -> OUTPUT, matching the contract permission matrix);
  only the token plumbing layer remains to be retired.
- `PrepareChallenge`: no V1 allowlist check on `challenge_kind` (contract §3.9 enables only
  `VerdictFraudProof`/`ProtocolFaultProof`).
- Error code texts and the Connect code for "past retention period" are not aligned (see §6).
