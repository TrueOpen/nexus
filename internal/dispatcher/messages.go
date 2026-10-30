package dispatcher

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/servicekey"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Wire message names of the signing projections the dispatcher uses.
const (
	ticketName        = "task.v1.DispatchTicketV1"
	recordName        = "task.v1.DispatchRecordV1"
	acceptName        = "task.v1.DispatchAcceptV1"
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

// signTicket signs t under key, with key's authorization nonce; its digest is the
// dispatch_ticket_hash.
func signTicket(key servicekey.Key, t *taskv1.DispatchTicketV1) ([]byte, [32]byte, error) {
	if key.Nonce == 0 {
		return nil, [32]byte{}, fmt.Errorf("sign %s: the service key has no authorization nonce yet", ticketName)
	}
	t.ServiceAuthorizationNonce = key.Nonce
	return signMessage(key.Signer, ticketName, t, func(sig []byte) { t.BuilderServiceSignature = sig })
}

// signRecord signs r under key, with key's authorization nonce; its digest is the
// dispatch_record_hash.
func signRecord(key servicekey.Key, r *taskv1.DispatchRecordV1) ([]byte, [32]byte, error) {
	if key.Nonce == 0 {
		return nil, [32]byte{}, fmt.Errorf("sign %s: the service key has no authorization nonce yet", recordName)
	}
	r.ServiceAuthorizationNonce = key.Nonce
	return signMessage(key.Signer, recordName, r, func(sig []byte) { r.BuilderServiceSignature = sig })
}

// signTicketBound signs m, a message bound to a ticket of nonce ticketNonce, under key with key's
// authorization nonce (set through setNonce). A key of an older generation than the ticket signs
// nothing: the message could never verify.
func signTicketBound(key servicekey.Key, ticketNonce uint64, name string, m proto.Message, setNonce func(uint64), setSig func([]byte)) ([]byte, [32]byte, error) {
	if key.Nonce == 0 {
		return nil, [32]byte{}, fmt.Errorf("sign %s: the service key has no authorization nonce yet", name)
	}
	if key.Nonce < ticketNonce {
		return nil, [32]byte{}, fmt.Errorf("sign %s: service key nonce %d is older than the ticket's %d", name, key.Nonce, ticketNonce)
	}
	setNonce(key.Nonce)
	return signMessage(key.Signer, name, m, setSig)
}

// signInputResponse signs r under key; ticketNonce is the nonce of the ticket r answers.
func signInputResponse(key servicekey.Key, ticketNonce uint64, r *nexusv1.DispatchInputResponseV1) ([]byte, [32]byte, error) {
	return signTicketBound(key, ticketNonce, inputResponseName, r,
		func(n uint64) { r.ServiceAuthorizationNonce = n }, func(sig []byte) { r.BuilderServiceSignature = sig })
}

// SignRecordResultNotice signs n under key, with key's authorization nonce, and returns its signed
// bytes and signing digest; ticketNonce is the nonce of the ticket n reports on.
func SignRecordResultNotice(key servicekey.Key, ticketNonce uint64, n *nexusv1.RecordResultNoticeV1) ([]byte, [32]byte, error) {
	return signTicketBound(key, ticketNonce, noticeName, n,
		func(nonce uint64) { n.ServiceAuthorizationNonce = nonce }, func(sig []byte) { n.BuilderServiceSignature = sig })
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
