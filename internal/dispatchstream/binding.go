package dispatchstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/TrueOpen/wire/dispatch"
	"google.golang.org/protobuf/proto"

	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/internal/kv"
)

const (
	bindingMessage = "nexus.v1.DispatchStreamBindingV1"
	bindKeyPrefix  = "bind|"
)

// verifyBinding checks the first frame of a stream: a DispatchStreamBindingV1 of schema version 1
// with a 32-byte stream_nonce, carried with cursor 0, for this chain and this Builder, signed over
// its wire signing digest by the cortex operator's current ACTIVE CORTEX key under that key's
// authorization nonce (wire VerifyDispatchStreamBinding: a revoked, previous or pending key never
// authorizes a stream). It does not record the binding (see claimBindingLocked).
func (h *Hub) verifyBinding(ctx context.Context, frame *nexusv1.DispatchStreamFrameV1) (*nexusv1.DispatchStreamBindingV1, error) {
	binding := frame.GetBinding()
	switch {
	case binding == nil:
		return nil, fmt.Errorf("%w: the first frame must be a binding", ErrBindingInvalid)
	case frame.GetCursor() != 0:
		return nil, fmt.Errorf("%w: the binding frame must carry cursor 0", ErrBindingInvalid)
	case binding.GetSchemaVersion() != dispatch.StreamSchemaVersion:
		return nil, fmt.Errorf("%w: schema_version %d", ErrBindingInvalid, binding.GetSchemaVersion())
	case binding.GetChainId() != h.cfg.ChainID:
		return nil, fmt.Errorf("%w: chain_id %q is not this chain", ErrBindingInvalid, binding.GetChainId())
	case h.cfg.BuilderOperator == "" || binding.GetBuilderOperator() != h.cfg.BuilderOperator:
		return nil, fmt.Errorf("%w: builder_operator is not this Builder", ErrBindingInvalid)
	case len(binding.GetStreamNonce()) != dispatch.StreamNonceSize:
		return nil, fmt.Errorf("%w: stream_nonce must be %d bytes", ErrBindingInvalid, dispatch.StreamNonceSize)
	case !bytes.Equal(frame.GetStreamNonce(), binding.GetStreamNonce()):
		return nil, fmt.Errorf("%w: frame stream_nonce differs from the binding", ErrBindingInvalid)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrBindingInvalid, err)
	}
	if err := dispatch.VerifyDispatchStreamBinding(h.cfg.ChainID, h.cfg.BuilderOperator, raw, h.keys.ProofOptions(ctx, nil)); err != nil {
		if errors.Is(err, ErrTransient) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrBindingInvalid, err)
	}
	return binding, nil
}

// checkBindingKey ends nothing while the CORTEX key that authenticated s's binding is still its
// operator's current ACTIVE key. Otherwise (the Cortex rotated, or its key was revoked or is gone)
// it returns ErrBindingKeyRetired: a binding is checked once per connection, so the stream must
// not outlive its key. A chain that cannot answer ends nothing.
func (h *Hub) checkBindingKey(ctx context.Context, s *session) error {
	key, err := h.keys.CurrentCortexKey(ctx, s.operator)
	switch {
	case errors.Is(err, ErrTransient):
		return nil
	case err != nil:
		return fmt.Errorf("%w: %v", ErrBindingKeyRetired, err)
	case key.AuthorizationNonce != s.bindingNonce:
		return fmt.Errorf("%w: current nonce %d, bound under %d", ErrBindingKeyRetired, key.AuthorizationNonce, s.bindingNonce)
	}
	return nil
}

// claimBindingLocked records (operator, nonce, stream_nonce) once; a second use of the same binding is
// refused, so a captured binding cannot open another stream. Markers of older nonces are dropped:
// a binding must name the current nonce, so they can never match again. Caller holds h.mu.
func (h *Hub) claimBindingLocked(binding *nexusv1.DispatchStreamBindingV1) error {
	operator, nonce := binding.GetCortexOperator(), binding.GetServiceAuthorizationNonce()
	key := bindKey(operator, nonce, binding.GetStreamNonce())
	_, used, err := h.store.GetWithError(kv.NSStreamSession, key)
	if err != nil {
		return fmt.Errorf("%w: read stream binding marker: %v", ErrTransient, err)
	}
	if used {
		return fmt.Errorf("%w: binding already used", ErrBindingInvalid)
	}
	ops := []kv.WriteOp{{NS: kv.NSStreamSession, Key: key, Val: []byte{1}}}
	prefix := bindKeyPrefix + operator + "|"
	if err := h.store.Scan(kv.NSStreamSession, func(k string, _ []byte) bool {
		if rest, ok := strings.CutPrefix(k, prefix); ok {
			if old, _, ok := strings.Cut(rest, "|"); ok {
				if n, err := strconv.ParseUint(old, 10, 64); err == nil && n < nonce {
					ops = append(ops, kv.WriteOp{NS: kv.NSStreamSession, Key: k, Delete: true})
				}
			}
		}
		return true
	}); err != nil {
		return fmt.Errorf("%w: scan stream binding markers: %v", ErrTransient, err)
	}
	if err := h.store.WriteBatch(ops...); err != nil {
		return fmt.Errorf("%w: write stream binding marker: %v", ErrTransient, err)
	}
	return nil
}

func bindKey(operator string, nonce uint64, streamNonce []byte) string {
	return bindKeyPrefix + operator + "|" + strconv.FormatUint(nonce, 10) + "|" + hex.EncodeToString(streamNonce)
}
