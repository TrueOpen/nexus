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

## Streaming OUTPUT data plane (ADR-0017)

`UploadTaskOutputStream`, `OutputStreamHeaderV1` / `OutputChunkV1` / `OutputFinV1`,
`SubscribeOutput`'s `resume_after_seq` and `frame`, `AckOutput`'s `last_seq`, and
`SubmitInferReceiptResponse.output_storage_confirmation` match TrueOpen/wire v0.1.1, except that
`OutputFinV1.finish_reason` / `worker_signature` (signed output fin) are not adopted yet.
The whole-plaintext fields (1-7) of `SubscribeOutputResponse` are deprecated.

## Authoritative contract

`proto/nexus/v1/*.proto` (in this repository) is the single authoritative
contract; the code in this directory is generated from those protos by `buf generate`,
so do not hand-edit it. Where any document disagrees with the protos, the protos win.

## How to consume

```go
import (
    nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
    "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
)
```

No release is tagged yet. Until the first `gen/trueopen/vX.Y.Z` tag (the Go nested-module
tag convention), develop against a local checkout with a `replace` directive rather than pinning
a commit.

## Private repository access

This repository is private, so build machines need:

```bash
export GOPRIVATE=github.com/TrueOpen/*
```

plus working GitHub git credentials (any of `~/.netrc`, a credential helper, or an SSH
key). A host without credentials (some devnet machines, for example) cannot `go build` a
project that depends on this module and can only run binaries built elsewhere.
