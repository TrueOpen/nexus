package attempt

import (
	"fmt"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Wire message names of the signing projections the book uses.
const (
	ticketName       = "task.v1.DispatchTicketV1"
	acceptName       = "task.v1.DispatchAcceptV1"
	resultHeaderName = "nexus.v1.DispatchResultHeaderV1"
)

func marshal(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

// digestOf is the wire signing digest of m under name; the signature fields never enter it.
func digestOf(name string, m proto.Message) ([32]byte, error) {
	raw, err := marshal(m)
	if err != nil {
		return [32]byte{}, fmt.Errorf("encode %s: %w", name, err)
	}
	digest, err := dispatch.SigningDigest(name, raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%s signing digest: %w", name, err)
	}
	return digest, nil
}

// SignResultHeader signs h with the Builder service key over its wire signing digest and returns
// the signed bytes. Any signature h carries is replaced.
func SignResultHeader(s signer.Signer, h *nexusv1.DispatchResultHeaderV1) ([]byte, error) {
	h.BuilderServiceSignature = nil
	digest, err := digestOf(resultHeaderName, h)
	if err != nil {
		return nil, err
	}
	sig, err := s.SignDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("sign %s: %w", resultHeaderName, err)
	}
	h.BuilderServiceSignature = sig
	return marshal(h)
}
