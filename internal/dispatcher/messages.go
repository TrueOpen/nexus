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

func signInputResponse(s signer.Signer, r *nexusv1.DispatchInputResponseV1) ([]byte, [32]byte, error) {
	return signMessage(s, inputResponseName, r, func(sig []byte) { r.BuilderServiceSignature = sig })
}

// SignRecordResultNotice signs n with the Builder service key and returns its signed bytes and
// signing digest.
func SignRecordResultNotice(s signer.Signer, n *nexusv1.RecordResultNoticeV1) ([]byte, [32]byte, error) {
	return signMessage(s, noticeName, n, func(sig []byte) { n.BuilderServiceSignature = sig })
}

// ResignTransport signs the Builder transport messages of a stored downlink frame again with s,
// in place: input responses and record notices carry no key generation, so after a service key
// cutover only the current key vouches for them. Offers keep their signature (a ticket is bound to
// the generation that issued it), and so does everything else.
func ResignTransport(s signer.Signer) func(*nexusv1.DispatchStreamFrameV1) error {
	return func(frame *nexusv1.DispatchStreamFrameV1) error {
		switch m := frame.GetMessage().(type) {
		case *nexusv1.DispatchStreamFrameV1_InputResponse:
			_, _, err := signInputResponse(s, m.InputResponse)
			return err
		case *nexusv1.DispatchStreamFrameV1_RecordResult:
			_, _, err := SignRecordResultNotice(s, m.RecordResult)
			return err
		}
		return nil
	}
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
