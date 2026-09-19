package taskdata

import (
	"context"
	"errors"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/signer"
)

// A Cortex node signs task data requests with the current service key under the CORTEX
// domain; the operator private key need not be online. Covers the metadata / download /
// upload request paths on both the Worker and Verifier sides.
func TestAuthorizerAcceptsCortexServiceKeySignedRequests(t *testing.T) {
	ctx := context.Background()

	t.Run("worker service key on metadata download and output upload", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		input := fx.metadata[ObjectKindInput]

		metadata := input
		request := signedRequestAs(t, fx.worker.Address(), fx.workerService, MethodGetMetadata, input.Key, metadataBody(t, input.Key), 70, 110)
		if err := fx.authorizer.AuthorizeMetadata(ctx, request, &metadata); err != nil {
			t.Fatalf("worker service key metadata: %v", err)
		}

		rangeRequestRange := &ByteRange{Offset: 0, Length: 64}
		rangeRequest := fetchRequestAs(t, fx.worker.Address(), fx.workerService, input.Key, rangeRequestRange, 71, 110)
		if _, err := fx.authorizer.AuthorizeFetch(ctx, rangeRequest, rangeRequestRange); err != nil {
			t.Fatalf("worker service key download: %v", err)
		}

		output := fx.metadata[ObjectKindOutput]
		receipt := validReceipt(t, fx, output)
		header := UploadHeader{
			Key: output.Key, SizeBytes: output.SizeBytes, SemanticHash: output.SemanticHash,
			MediaType: output.MediaType, Receipt: &receipt,
		}
		digest, err := UploadBodyDigest(header)
		if err != nil {
			t.Fatal(err)
		}
		upload := signedRequestAs(t, fx.worker.Address(), fx.workerService, MethodUpload, output.Key, digest[:], 72, 110)
		if _, _, err := fx.authorizer.AuthorizeUploadObject(ctx, upload, header); err != nil {
			t.Fatalf("worker service key output upload: %v", err)
		}
	})

	t.Run("verifier service key on metadata download and evidence upload", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		output := fx.metadata[ObjectKindOutput]

		metadata := output
		request := signedRequestAs(t, fx.verifier.Address(), fx.verifierService, MethodGetMetadata, output.Key, metadataBody(t, output.Key), 73, 110)
		if err := fx.authorizer.AuthorizeMetadata(ctx, request, &metadata); err != nil {
			t.Fatalf("verifier service key metadata: %v", err)
		}

		rangeRequestRange := &ByteRange{Offset: 0, Length: 32}
		rangeRequest := fetchRequestAs(t, fx.verifier.Address(), fx.verifierService, output.Key, rangeRequestRange, 74, 110)
		if _, err := fx.authorizer.AuthorizeFetch(ctx, rangeRequest, rangeRequestRange); err != nil {
			t.Fatalf("verifier service key download: %v", err)
		}

		// A Verifier may only upload its own bundle: producer_kind=VERIFIER, producer_operator=itself.
		evidence := fx.metadata[ObjectKindEvidenceManifest]
		evidence.Key.EvidenceProducerKind = EvidenceProducerVerifier
		evidence.Key.ProducerOperator = fx.verifier.Address()
		header := UploadHeader{
			Key: evidence.Key, SizeBytes: evidence.SizeBytes, SemanticHash: evidence.SemanticHash,
			MediaType: evidence.MediaType,
		}
		digest, err := UploadBodyDigest(header)
		if err != nil {
			t.Fatal(err)
		}
		upload := signedRequestAs(t, fx.verifier.Address(), fx.verifierService, MethodUpload, evidence.Key, digest[:], 75, 110)
		if _, _, err := fx.authorizer.AuthorizeUploadObject(ctx, upload, header); err != nil {
			t.Fatalf("verifier service key evidence upload: %v", err)
		}
	})

	// Operator self-signing is an explicitly retained compatibility path, not the only path:
	// a plain User only has a wallet key and no service key, so this path must keep working.
	t.Run("operator self-signed requests still pass", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		for _, caller := range []signer.Signer{fx.worker, fx.verifier, fx.user} {
			metadata := fx.metadata[ObjectKindOutput]
			request := fx.fixtureRequest(t, caller, MethodGetMetadata, metadata.Key, nil, 76, 110)
			if err := fx.authorizer.AuthorizeMetadata(ctx, request, &metadata); err != nil {
				t.Fatalf("operator self-signed metadata for %s: %v", caller.Address(), err)
			}
		}
	})
}

// Any failure of the triple service key check (state, pubkey, derived address) must reject,
// and must not silently fall back to the operator self-signed path.
func TestAuthorizerRejectsInvalidCortexServiceKeys(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*authorizerFixture)
	}{
		{
			name: "service key is not ACTIVE",
			mutate: func(fx *authorizerFixture) {
				state := participantServiceKey(participantTypeCortex, fx.worker.Address(), fx.workerService)
				state.Status = "REVOKED"
				fx.authority.setServiceKey(state)
			},
		},
		{
			name: "presented key differs from the on-chain ServicePubKey",
			mutate: func(fx *authorizerFixture) {
				fx.authority.setServiceKey(participantServiceKey(participantTypeCortex, fx.worker.Address(), fx.other))
			},
		},
		{
			name: "derived address differs from the on-chain ServiceAddress",
			mutate: func(fx *authorizerFixture) {
				state := participantServiceKey(participantTypeCortex, fx.worker.Address(), fx.workerService)
				state.ServiceAddress = fx.other.Address()
				fx.authority.setServiceKey(state)
			},
		},
		{
			// The old implementation looked up the WORKER domain. A key registered only there
			// must not be found and must be rejected, proving the lookup domain is CORTEX with
			// no fallback to the sender_role domain or operator self-signing.
			name: "key is only registered under the WORKER sender_role domain",
			mutate: func(fx *authorizerFixture) {
				delete(fx.authority.keys, participantTypeCortex+"|"+fx.worker.Address())
				fx.authority.setServiceKey(participantServiceKey("WORKER", fx.worker.Address(), fx.workerService))
			},
		},
		{
			name: "service key belongs to another operator",
			mutate: func(fx *authorizerFixture) {
				delete(fx.authority.keys, participantTypeCortex+"|"+fx.worker.Address())
				fx.authority.setServiceKey(participantServiceKey(participantTypeCortex, fx.other.Address(), fx.workerService))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fx := newAuthorizerFixture(t)
			tt.mutate(fx)

			metadata := fx.metadata[ObjectKindInput]
			request := signedRequestAs(t, fx.worker.Address(), fx.workerService, MethodGetMetadata, metadata.Key, metadataBody(t, metadata.Key), 80, 110)
			if err := fx.authorizer.AuthorizeMetadata(ctx, request, &metadata); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("metadata error = %v, want ErrUnauthorized", err)
			}
			rangeRequestRange := &ByteRange{Offset: 0, Length: 64}
			rangeRequest := fetchRequestAs(t, fx.worker.Address(), fx.workerService, metadata.Key, rangeRequestRange, 81, 110)
			if _, err := fx.authorizer.AuthorizeFetch(ctx, rangeRequest, rangeRequestRange); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("download error = %v, want ErrUnauthorized", err)
			}

			// Since wire v0.4.1 the operator self-signed compatibility path no longer exists:
			// the CORTEX_SERVICE public key is fetched from the chain only by (CORTEX,
			// requester_address), and requester_kind alone selects the verification path.
			// After the service key is rejected there is no second path; this is the
			// observable form of "never sniff by signature length, never try the other path
			// after one fails".
			selfSigned := fx.metadata[ObjectKindInput]
			if err := fx.authorizer.AuthorizeMetadata(ctx,
				signedRequestAs(t, fx.worker.Address(), fx.worker, MethodGetMetadata, selfSigned.Key, metadataBody(t, selfSigned.Key), 82, 110),
				&selfSigned); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("operator self-signed metadata error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

// When the chain lookup fails the service key cannot be checked; it must fail closed and
// report the chain lookup as unavailable, not degrade to "no service key" and either admit
// the request or misreport an authorization rejection.
func TestAuthorizerFailsClosedWhenServiceKeyLookupIsUnavailable(t *testing.T) {
	fx := newAuthorizerFixture(t)
	metadata := fx.metadata[ObjectKindInput]
	request := signedRequestAs(t, fx.worker.Address(), fx.workerService, MethodGetMetadata, metadata.Key, metadataBody(t, metadata.Key), 83, 110)
	fx.authority.err = errors.New("node offline")
	if err := fx.authorizer.AuthorizeMetadata(context.Background(), request, &metadata); !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("service key outage error = %v, want ErrAuthorityUnavailable", err)
	}
}

// The InferReceipt service_signature is issued by the Worker node's current service key
// under the CORTEX domain; signing with the operator key, or a key registered only under
// the WORKER domain, must both be rejected.
func TestAuthorizerReceiptRequiresCortexServiceKeySignature(t *testing.T) {
	ctx := context.Background()

	uploadReceipt := func(t *testing.T, fx *authorizerFixture, receipt SignedInferReceipt, nonce byte) error {
		t.Helper()
		output := fx.metadata[ObjectKindOutput]
		header := UploadHeader{
			Key: output.Key, SizeBytes: output.SizeBytes, SemanticHash: output.SemanticHash,
			MediaType: output.MediaType, Receipt: &receipt,
		}
		digest, err := UploadBodyDigest(header)
		if err != nil {
			t.Fatal(err)
		}
		request := fx.fixtureRequest(t, fx.worker, MethodUpload, output.Key, digest[:], nonce, 110)
		_, _, err = fx.authorizer.AuthorizeUploadObject(ctx, request, header)
		return err
	}

	t.Run("receipt signed by the operator key is rejected", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		receipt := receiptSignedBy(t, fx.worker.Address(), fx.worker, fx.metadata[ObjectKindOutput])
		if err := uploadReceipt(t, fx, receipt, 90); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("operator-signed receipt error = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("key registered only under the WORKER domain is not found", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		delete(fx.authority.keys, participantTypeCortex+"|"+fx.worker.Address())
		fx.authority.setServiceKey(participantServiceKey("WORKER", fx.worker.Address(), fx.workerService))
		receipt := validReceipt(t, fx, fx.metadata[ObjectKindOutput])
		// The same service key signs both the request and the receipt: when the key is
		// invalid, request authorization rejects first and the receipt step is never
		// reached. Fail-closed happens earlier, not with weaker coverage.
		if err := uploadReceipt(t, fx, receipt, 91); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("WORKER-domain receipt error = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("revoked service key is rejected", func(t *testing.T) {
		fx := newAuthorizerFixture(t)
		state := participantServiceKey(participantTypeCortex, fx.worker.Address(), fx.workerService)
		state.Status = "REVOKED"
		fx.authority.setServiceKey(state)
		receipt := validReceipt(t, fx, fx.metadata[ObjectKindOutput])
		// The same service key signs both the request and the receipt: when the key is
		// invalid, request authorization rejects first and the receipt step is never
		// reached. Fail-closed happens earlier, not with weaker coverage.
		if err := uploadReceipt(t, fx, receipt, 92); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("revoked service key receipt error = %v, want ErrUnauthorized", err)
		}
	})
}

// The state produced by participantServiceKey must match the actual chaincli.ServiceKeyState
// fields, otherwise the cases above would pass under a false premise.
func TestParticipantServiceKeyFixtureShape(t *testing.T) {
	fx := newAuthorizerFixture(t)
	state, found := fx.authority.keys[participantTypeCortex+"|"+fx.worker.Address()]
	if !found {
		t.Fatal("worker CORTEX service key must be registered by the fixture")
	}
	if state.ParticipantType != "CORTEX" || state.OperatorAddress != fx.worker.Address() ||
		state.ServiceAddress != fx.workerService.Address() || state.Status != "ACTIVE" {
		t.Fatalf("unexpected fixture service key: %#v", state)
	}
	if _, err := fx.authority.QueryCurrentServiceKey(context.Background(), "WORKER", fx.worker.Address()); !errors.Is(err, chaincli.ErrNotFound) {
		t.Fatalf("WORKER domain lookup error = %v, want chaincli.ErrNotFound", err)
	}
}
