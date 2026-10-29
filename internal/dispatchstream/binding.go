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
	bindingMessage       = "nexus.v1.DispatchStreamBindingV1"
	bindingSchemaVersion = 1
	maxStreamNonceBytes  = 64
	bindKeyPrefix        = "bind|"
)

// verifyBinding checks the first frame of a stream: a DispatchStreamBindingV1 for this chain and
// this Builder, signed over its wire signing digest by the cortex operator's current CORTEX key
// with that key's authorization nonce. It does not record the binding (see claimBindingLocked).
func (h *Hub) verifyBinding(ctx context.Context, frame *nexusv1.DispatchStreamFrameV1) (*nexusv1.DispatchStreamBindingV1, error) {
	binding := frame.GetBinding()
	switch {
	case binding == nil:
		return nil, fmt.Errorf("%w: the first frame must be a binding", ErrBindingInvalid)
	case binding.GetSchemaVersion() != bindingSchemaVersion:
		return nil, fmt.Errorf("%w: schema_version %d", ErrBindingInvalid, binding.GetSchemaVersion())
	case binding.GetChainId() != h.cfg.ChainID:
		return nil, fmt.Errorf("%w: chain_id %q is not this chain", ErrBindingInvalid, binding.GetChainId())
	case h.cfg.BuilderOperator == "" || binding.GetBuilderOperator() != h.cfg.BuilderOperator:
		return nil, fmt.Errorf("%w: builder_operator is not this Builder", ErrBindingInvalid)
	case len(binding.GetStreamNonce()) == 0 || len(binding.GetStreamNonce()) > maxStreamNonceBytes:
		return nil, fmt.Errorf("%w: stream_nonce must be 1..%d bytes", ErrBindingInvalid, maxStreamNonceBytes)
	case !bytes.Equal(frame.GetStreamNonce(), binding.GetStreamNonce()):
		return nil, fmt.Errorf("%w: frame stream_nonce differs from the binding", ErrBindingInvalid)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrBindingInvalid, err)
	}
	digest, err := dispatch.SigningDigest(bindingMessage, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBindingInvalid, err)
	}
	key, err := h.keys.CurrentCortexKey(ctx, binding.GetCortexOperator())
	if err != nil {
		if errors.Is(err, ErrTransient) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrBindingInvalid, err)
	}
	if binding.GetServiceAuthorizationNonce() != key.AuthorizationNonce {
		return nil, fmt.Errorf("%w: service_authorization_nonce %d is not the current %d",
			ErrBindingInvalid, binding.GetServiceAuthorizationNonce(), key.AuthorizationNonce)
	}
	if err := dispatch.VerifyDigestSignature(key.PubKey, digest[:], binding.GetServiceSignature()); err != nil {
		return nil, fmt.Errorf("%w: service_signature: %v", ErrBindingInvalid, err)
	}
	return binding, nil
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
