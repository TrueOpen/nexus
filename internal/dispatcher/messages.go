package dispatcher

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Wire message names of the signing projections the dispatcher uses.
const (
	ticketName        = "task.v1.DispatchTicketV1"
	recordName        = "task.v1.DispatchRecordV1"
	acceptName        = "task.v1.DispatchAcceptV1"
	resultHeaderName  = "nexus.v1.DispatchResultHeaderV1"
	inputResponseName = "nexus.v1.DispatchInputResponseV1"
	noticeName        = "nexus.v1.RecordResultNoticeV1"

	schemaVersion = 1
)

func marshal(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

// signMessage signs m with the Builder service key over its wire signing digest under name,
// stores the signature through setSig and returns the signed bytes and the digest. The signature
// never enters its own digest.
func signMessage(s signer.Signer, name string, m proto.Message, setSig func([]byte)) ([]byte, [32]byte, error) {
	setSig(nil)
	unsigned, err := marshal(m)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("encode %s: %w", name, err)
	}
	digest, err := dispatch.SigningDigest(name, unsigned)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("%s signing digest: %w", name, err)
	}
	sig, err := s.SignDigest(digest)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("sign %s: %w", name, err)
	}
	setSig(sig)
	raw, err := marshal(m)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("encode %s: %w", name, err)
	}
	return raw, digest, nil
}

// signTicket signs t; its digest is the dispatch_ticket_hash.
func signTicket(s signer.Signer, t *taskv1.DispatchTicketV1) ([]byte, [32]byte, error) {
	return signMessage(s, ticketName, t, func(sig []byte) { t.BuilderServiceSignature = sig })
}

// signRecord signs r; its digest is the dispatch_record_hash.
func signRecord(s signer.Signer, r *taskv1.DispatchRecordV1) ([]byte, [32]byte, error) {
	return signMessage(s, recordName, r, func(sig []byte) { r.BuilderServiceSignature = sig })
}

func signResultHeader(s signer.Signer, h *nexusv1.DispatchResultHeaderV1) ([]byte, [32]byte, error) {
	return signMessage(s, resultHeaderName, h, func(sig []byte) { h.BuilderServiceSignature = sig })
}

func signInputResponse(s signer.Signer, r *nexusv1.DispatchInputResponseV1) ([]byte, [32]byte, error) {
	return signMessage(s, inputResponseName, r, func(sig []byte) { r.BuilderServiceSignature = sig })
}

// SignRecordResultNotice signs n with the Builder service key and returns its signed bytes and
// signing digest.
func SignRecordResultNotice(s signer.Signer, n *nexusv1.RecordResultNoticeV1) ([]byte, [32]byte, error) {
	return signMessage(s, noticeName, n, func(sig []byte) { n.BuilderServiceSignature = sig })
}

// memberRef is the CandidateMemberRefV1 of a pool member in the snapshot.
func memberRef(snapshotID []byte, m dispatch.RosterMember) *taskv1.CandidateMemberRefV1 {
	return &taskv1.CandidateMemberRefV1{
		CandidatePoolSnapshotId: append([]byte(nil), snapshotID...),
		Slot:                    m.Slot,
		SlotVersion:             m.SlotVersion,
		OperatorAddress:         m.OperatorAddress,
	}
}
