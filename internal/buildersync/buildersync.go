// Package buildersync keeps the members of an order's Task Builders group in step with the
// order's dispatching Builder.
//
// The group is every member of the BuilderSet snapshot the order signs in; the dispatching
// Builder is one of them. The other members hold what they need to stand in for it: the round
// rosters with the handraise roots they bind and the input copy from the first ticket of a round
// on, every ticket and what came of it (the Worker's reject, the winner's accept), the signed
// record, and, only once the chain admitted the order's dispatch entry, the user's signed order
// (a member holding it earlier could take the session over) with the dispatching Builder's
// RECORDED result header, then the recorded winner's output frame by frame. A member rebuts
// compensation claims and answers ROSTER_UNAVAILABLE challenges from its copy (package
// dispatchresponse), serves GetDispatchRoster from it and resumes the user's output stream from
// its replica after the record.
//
// The Sender runs on the dispatching Builder. Every change of an order becomes numbered items of
// the order's sync stream, stored in an outbox before anything is sent and retried with backoff
// until every member acknowledged them; a member that stays behind is logged as an error, and
// nothing here ever holds up dispatching. The Receiver runs on every member: it checks that a
// batch comes from the order's dispatching Builder, signed by its current service key, for a
// group this Builder is in, checks every ticket, roster, root, input and output frame against
// what the dispatching Builder and the winner signed, and applies the items in order, each once;
// an item sent again must be the item applied at its sequence.
//
// The service is wire's nexus.v1.BuilderSyncService. A batch is signed over its canonical typed
// projection, not its protobuf bytes, and a receiver validates the exact request bytes strictly
// (no unknown or duplicate fields) before decoding them.
package buildersync

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/signer"
)

// schemaVersion is the BuilderSyncBatchV1 schema this package writes and reads.
const schemaVersion = 1

// MaxRequestBytes bounds a complete SyncRequest; a batch also holds at most
// dispatch.MaxBuilderSyncEntries items and as many output chunks.
const MaxRequestBytes = 1 << 20

// Wire message names of the signing projections checked here.
const (
	ticketName       = "task.v1.DispatchTicketV1"
	acceptName       = "task.v1.DispatchAcceptV1"
	rejectName       = "task.v1.DispatchRejectV1"
	recordName       = "task.v1.DispatchRecordV1"
	rootName         = "task.v1.SignedHandraiseRootV1"
	resultHeaderName = "nexus.v1.DispatchResultHeaderV1"
	// requestName is the signed sync request: the sender's current BUILDER service key signs
	// H_FIELDS_V1("TRUEOPEN_NEXUS_BUILDER_SYNC_V1", chain_id, raw20(sender), canonical batch).
	requestName = "nexus.v1.SyncRequest"
)

var (
	// ErrUnauthenticated refuses a batch that is not signed by its sender's current service key.
	ErrUnauthenticated = errors.New("NEXUS_BUILDER_SYNC_UNAUTHENTICATED")
	// ErrNotGroupMember refuses a batch whose sender or receiver is not a member of the BuilderSet
	// snapshot it names, or that names a snapshot that is not the current one.
	ErrNotGroupMember = errors.New("NEXUS_BUILDER_SYNC_NOT_GROUP_MEMBER")
	// ErrMalformed refuses a batch that does not parse or is not addressed to this Builder.
	ErrMalformed = errors.New("NEXUS_BUILDER_SYNC_MALFORMED")
	// ErrUnavailable means the batch could not be judged now (a chain read failed); the sender
	// tries again.
	ErrUnavailable = errors.New("NEXUS_BUILDER_SYNC_UNAVAILABLE")
)

// SignRequest signs a batch with the sender's current service key. The batch is checked against
// the wire contract on the way: a batch a receiver would refuse as malformed is never sent.
func SignRequest(s signer.Signer, batch *nexusv1.BuilderSyncBatchV1) (*nexusv1.SyncRequest, error) {
	req := &nexusv1.SyncRequest{Batch: batch}
	raw, err := marshal(req)
	if err != nil {
		return nil, err
	}
	digest, err := signingDigest(requestName, raw)
	if err != nil {
		return nil, err
	}
	if req.SenderSignature, err = s.SignDigest(digest); err != nil {
		return nil, fmt.Errorf("sign sync batch: %w", err)
	}
	return req, nil
}

func marshal(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

// signingDigest is the wire signing digest of exact message bytes.
func signingDigest(name string, raw []byte) ([32]byte, error) {
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%s signing digest: %w", name, err)
	}
	return digest, nil
}

func sum(b []byte) [32]byte { return sha256.Sum256(b) }

// streamKey names the sync stream of an order.
func streamKey(sessionID string, sequence uint64) string {
	return fmt.Sprintf("%s/%020d", sessionID, sequence)
}
