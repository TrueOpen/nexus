package builderreg

import (
	"context"
	"errors"
	"strings"
	"testing"

	sharedv1 "github.com/TrueOpen/nexus/gen/trueopen/shared/v1"

	"github.com/TrueOpen/nexus/internal/nodecontract"
)

// ADR-0015: changing the descriptor is an explicit operator-key action by the operator
// (`nexus builder register`); `nexus start` only checks that the on-chain descriptor matches the local
// configuration and sends no transaction at all.

func assertNoWrites(t *testing.T, sub *captureSubmitter) {
	t.Helper()
	if len(sub.registers)+len(sub.updates) != 0 {
		t.Fatalf("start must not submit: register=%d update=%d",
			len(sub.registers), len(sub.updates))
	}
}

func TestStartRefusesUnregisteredBuilderWithoutSubmitting(t *testing.T) {
	sg := testSigner(t)
	state := newBuilderState()
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))

	err := reg.Start(context.Background())
	if !errors.Is(err, ErrNotRegistered) || !strings.Contains(err.Error(), "nexus builder register") {
		t.Fatalf("Start on an unregistered Builder = %v, want ErrNotRegistered naming the CLI", err)
	}
	assertNoWrites(t, sub)
}

func TestStartAcceptsMatchingDescriptorWithoutSubmitting(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://builder.example")
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))

	if err := reg.Start(context.Background()); err != nil {
		t.Fatalf("Start with a matching descriptor: %v", err)
	}
	assertNoWrites(t, sub)
}

func TestStartRefusesDescriptorThatDiffersFromConfiguration(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://old.example")
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))

	err := reg.Start(context.Background())
	if !errors.Is(err, ErrDescriptorStale) || !strings.Contains(err.Error(), "nexus builder register") {
		t.Fatalf("Start with a stale descriptor = %v, want ErrDescriptorStale naming the CLI", err)
	}
	assertNoWrites(t, sub)
}

// TLS is enabled but the on-chain descriptor holds no fingerprint for this certificate: the TLS port must not be opened, so startup is refused.
func TestStartRefusesWhenCertificateFingerprintIsNotOnChain(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://builder.example") // no fingerprint registered on chain
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))
	pin := strings.Repeat("ab", 32)
	WithTLSPubKeyHash(pin)(reg)

	err := reg.Start(context.Background())
	if !errors.Is(err, ErrDescriptorStale) || !strings.Contains(err.Error(), "tls_pubkey_hash") {
		t.Fatalf("Start with an unregistered fingerprint = %v, want ErrDescriptorStale naming tls_pubkey_hash", err)
	}
	assertNoWrites(t, sub)
}

// The same fingerprint is already registered on chain: startup proceeds normally.
func TestStartAcceptsRegisteredCertificateFingerprint(t *testing.T) {
	sg := testSigner(t)
	pin := strings.Repeat("ab", 32)
	state := registeredBuilderState(sg, "https://builder.example")
	endpoints, err := derivedServiceEndpoints("https://builder.example", pin)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := nodecontract.ServiceDescriptorHash(
		sharedv1.ParticipantType_PARTICIPANT_TYPE_BUILDER, sg.Address(), 1,
		endpoints, nodecontract.DefaultServiceEndpointLimits())
	if err != nil {
		t.Fatal(err)
	}
	state.descriptor.Endpoints = endpoints
	state.descriptor.DescriptorHash = hash
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))
	WithTLSPubKeyHash(pin)(reg)

	if err := reg.Start(context.Background()); err != nil {
		t.Fatalf("Start with the registered fingerprint: %v", err)
	}
	assertNoWrites(t, sub)
}

// `nexus builder register` (Ensure) is still the one that submits: the fingerprint goes on chain with the descriptor.
func TestEnsureRegistersCertificateFingerprint(t *testing.T) {
	sg := testSigner(t)
	state := registeredBuilderState(sg, "https://builder.example")
	sub := &captureSubmitter{state: state}
	reg := newTestRegistrar(state, sub, sg, identityConfig("https://builder.example"))
	pin := strings.Repeat("ab", 32)
	WithTLSPubKeyHash(pin)(reg)

	if err := reg.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sub.updates) != 1 {
		t.Fatalf("updates = %d, want the descriptor update carrying the fingerprint", len(sub.updates))
	}
	for _, endpoint := range sub.updates[0].Endpoints {
		if endpoint.TLSPubKeyHash != pin {
			t.Fatalf("endpoint %s tls_pubkey_hash = %q, want %s", endpoint.URI, endpoint.TLSPubKeyHash, pin)
		}
	}
}
