# github.com/TrueOpen/nexus/gen/trueopen

The generated contract for the Nexus IngressAPI (Connect client/handler plus protobuf
types) together with the mirror of the Node's public wire (`task/v1`,
`shared/v1`, `hub/v1`), as a standalone Go module. IngressAPI relay messages
reference on-chain types, so consumers get everything by depending on this module alone.

The dependency surface is only `connectrpc.com/connect`, `google.golang.org/protobuf`
and two real wire types from cosmos-sdk (`cosmos.base.v1beta1.Coin`,
`cosmos.base.query.v1beta1.PageRequest`); it carries no dependency on the Nexus server
(chain client / NATS / storage), and `contract_guard_test.go` locks that down. The
mirrored protos strip the gogoproto / cosmos_proto / amino / google.api annotations —
they are generator options only and do not change the wire encoding, but they would drag
the whole Cosmos toolchain into consumers.

`bus/v1` (the bus payloads between Builders and Cortex) stays in the root module
`gen/bus` and is not part of this module.

## Streaming OUTPUT data plane (ADR-0017, types only)

`UploadTaskOutputStream`, `OutputStreamHeaderV1` / `OutputChunkV1` / `OutputFinV1`,
`SubscribeOutput`'s `resume_after_seq` and `frame`, `AckOutput`'s `last_seq`, and
`SubmitInferReceiptResponse.output_storage_confirmation` match TrueOpen/wire v0.1.1, except that
`OutputFinV1.finish_reason` / `worker_signature` (signed output fin) are not adopted yet.
`chunk_lengths` / `output_leaf_count` sit on `TaskDataMetadataV1` 9/10 with their
wire v0.3.0 numbering; v0.4.0 moves them to `TaskDataObjectMetadataV1` 5/6, and nexus
will migrate along with them when it adopts that message. The Nexus-side implementation
sits behind `task_data.output_stream.enabled`, which is off by default; while it is off
`UploadTaskOutputStream` returns Unimplemented. The whole-plaintext fields (1-7) of
`SubscribeOutputResponse` are deprecated.

## Authoritative contract

`proto/nexus/v1/*.proto` (in this repository) is the single authoritative
contract; the code in this directory is generated from those protos by `buf generate`,
so do not hand-edit it. Where any document disagrees with the protos, the protos win.

## Breaking change: InferReceipt reshaped (Keeper Interface Contract §5.14)

`SignedInferReceiptV1` and `EvidenceCommitmentV1` have moved to the frozen
`task.v1.InferReceiptV1` shape: field numbers were rearranged, 7 old fields were
removed and 7 were added, `required_evidence_commitments` moved from the request level
into the receipt, and the signature preimage became H_FIELDS_V1 typed framing.
**Consumers upgrading this module (Cortex) must change their signing in the same
batch**; old signatures are not accepted for compatibility.

For the byte-level description, the golden vector and the self-check steps, see
`docs/nexus-cortex-contract-migration.md` §10 in this repository.

## Breaking change: verify commit / result reshaped (initial relay implementation, Builder relays)

The request-level fields of `SubmitVerifyCommitRequest` / `SubmitVerifyResultRequest`
were removed (their field numbers are reserved) and replaced by
`SignedVerifyCommitV1` / `SignedResultReceiptV1`, which mirror the on-chain frozen
`task.v1.VerifyCommitV1` / `ResultReceiptV1` field for field. The request envelope
signing domains became `TRUEOPEN_SUBMIT_VERIFY_COMMIT_V2` /
`TRUEOPEN_SUBMIT_VERIFY_RESULT_V2`. The Builder relays them as a batch message, and the
response only means the batch was broadcast. See
`docs/nexus-cortex-contract-migration.md` §4-B.

## How to consume

```go
import (
    nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
    "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
)
```

```bash
go get github.com/TrueOpen/nexus/gen/trueopen@<commit>
```

Versions are pinned by commit for now; when needed we will publish tags of the form
`gen/trueopen/vX.Y.Z` (the Go nested-module tag convention), and a version number can then
replace the commit.

## Private repository access

This repository is private, so build machines need:

```bash
export GOPRIVATE=github.com/TrueOpen/*
```

plus working GitHub git credentials (any of `~/.netrc`, a credential helper, or an SSH
key). A host without credentials (some devnet machines, for example) cannot `go build` a
project that depends on this module and can only run binaries built elsewhere.
