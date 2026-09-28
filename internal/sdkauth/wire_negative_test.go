package sdkauth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/TrueOpen/nexus/internal/eip712"
	"github.com/TrueOpen/nexus/internal/wirefixture"
)

// wireNegativeCase is one row of request_auth_negative_cases in wire account_signing_v1.json.
type wireNegativeCase struct {
	Name      string `json:"name"`
	Base      string `json:"base"`
	Expect    string `json:"expect"`
	Error     string `json:"error"`
	Signature string `json:"signature_65"`
	Digest    string `json:"signing_digest"`
	Recovered string `json:"recovered_address"`
	Signed    *struct {
		Message map[string]string `json:"message"`
		Signer  string            `json:"signer"`
	} `json:"signed"`
	Verified *struct {
		Message map[string]string `json:"message"`
		Domain  map[string]string `json:"domain"`
	} `json:"verified"`
	Context *struct {
		CurrentHeight string `json:"current_height"`
		MaxBlocks     string `json:"max_session_grant_blocks"`
	} `json:"verification_context"`
	Transport map[string]string `json:"transport"`
}

// sdkNegativeSkipped are the rows this package does not decide: the Task data path (checked in
// internal/taskdata) and the OpenTask and ConfirmOpenTask rules the Ingress service applies
// (checked in internal/ingress).
var sdkNegativeSkipped = map[string]bool{
	"task_data_request_other_evm_chain_id":      true,
	"task_data_request_domain_version_1":        true,
	"task_data_upload_with_session_grant":       true,
	"task_data_input_object_with_session_grant": true,
	"open_task_task_id_not_derived":             true,
	"confirm_open_task_not_callable":            true,
}

var sdkErrors = []error{ErrMalformed, ErrSessionMethodNotAllowed, ErrSessionGrantInvalid, ErrSessionGrantExpired,
	ErrInvalidSignature, ErrExpired, ErrReplay}

// Every SDK request row of the wire reject table: where the row publishes the digest the verifier
// rebuilds and the address the signature recovers to, both are reproduced byte for byte, and Verify
// ends with the row's error code (or accepts an accept row).
func TestWireRequestAuthNegativeCases(t *testing.T) {
	var file struct {
		Cases []wireNegativeCase `json:"request_auth_negative_cases"`
	}
	if err := json.Unmarshal(wirefixture.ReadFile(t, filepath.Join("testdata", "v1", "shared", "account_signing_v1.json")), &file); err != nil {
		t.Fatal(err)
	}
	f := loadAccountSigning(t)
	seen := 0
	for _, row := range file.Cases {
		if sdkNegativeSkipped[row.Name] {
			continue
		}
		seen++
		t.Run(row.Name, func(t *testing.T) {
			// The request the row starts from: the wallet OpenTask request, or the session-key
			// SubscribeOutput request with its grant (also for rows about the grant itself).
			var e *Envelope
			var opts VerifyOpts
			if row.Base == "sdk_request" {
				e = envelopeFrom(t, f.SDKRequest)
				opts = optsFor(t, f, f.SDKRequest, chainFor(t, f))
				opts.AllowHeightExpiry = true
			} else {
				e = envelopeFrom(t, f.SDKRequestSession)
				e.SessionGrant = grantFrom(t, f)
				opts = optsFor(t, f, f.SDKRequestSession, chainFor(t, f))
				opts.SessionAllowed = true
			}
			grantRow := row.Base == "session_grant"

			// What the signer signed, as the transport carries it.
			if row.Signed != nil {
				sig := mustHex(t, row.Signature)
				if grantRow {
					e.SessionGrant.UserSignature = sig
				} else {
					e.Signature = sig
				}
				for k, v := range row.Signed.Message {
					switch {
					case grantRow && k == "chainId":
						e.SessionGrant.ChainID = v
					case k == "expiryHeightOrTime":
						n, err := strconv.ParseInt(v, 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						e.ExpiryHeightOrTime = n
					case k == "endpoint":
						e.Endpoint = v
					case k == "taskId":
						e.TaskID = v
					case k == "sessionGrantHash":
						// A session key signing with the grant hash carries the grant; the wallet
						// signing it without a grant carries none; a zero hash keeps the base grant.
						if row.Signed.Signer == "session_key" && e.SessionGrant == nil {
							e.SessionGrant = grantFrom(t, f)
						}
					}
				}
			}
			for k, v := range row.Transport {
				switch k {
				case "session_id":
					e.SessionID = v
				case "task_id":
					e.TaskID = v
				case "request_nonce_hex":
					e.RequestNonce = mustHex(t, v)
				case "expiry_height_or_time":
					n, err := strconv.ParseInt(v, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					e.ExpiryHeightOrTime = n
				default:
					t.Fatalf("unhandled transport field %q", k)
				}
			}
			// What the verifier rebuilds.
			if row.Verified != nil {
				for k, v := range row.Verified.Message {
					switch k {
					case "chainId":
						if !grantRow {
							opts.ChainID = v
						}
					case "bodyDigest":
						opts.Body = hash32(t, v)
					}
				}
				if v, ok := row.Verified.Domain["chain_id"]; ok {
					opts.EVMChainID = mustUint(t, v)
				}
			}
			if row.Context != nil {
				opts.Chain.(*fakeChain).height = mustUint(t, row.Context.CurrentHeight)
				opts.MaxSessionGrantBlocks = mustUint(t, row.Context.MaxBlocks)
			}

			// Byte for byte: the digest the verifier rebuilds and the address the signature
			// recovers to over it.
			if row.Digest != "" {
				var digest [32]byte
				var sig []byte
				if grantRow {
					d, err := SessionGrantDigest(e.SessionGrant, opts.EVMChainID)
					if err != nil {
						t.Fatal(err)
					}
					digest, sig = d, e.SessionGrant.UserSignature
				} else {
					var grantHash [32]byte
					if e.SessionGrant != nil {
						h, err := SessionGrantHash(e.SessionGrant)
						if err != nil {
							t.Fatal(err)
						}
						grantHash = h
					}
					rebuilt := *e
					rebuilt.ChainID = opts.ChainID
					d, err := RequestDigest(&rebuilt, opts.Body, grantHash, opts.EVMChainID)
					if err != nil {
						if errors.Is(err, ErrMalformed) {
							goto verify // the row is refused before any typed data exists
						}
						t.Fatal(err)
					}
					digest, sig = d, e.Signature
				}
				if got := hex.EncodeToString(digest[:]); got != row.Digest {
					t.Fatalf("signing_digest = %s, want %s", got, row.Digest)
				}
				recovered, err := eip712.Recover(digest, sig)
				if err != nil || hex.EncodeToString(recovered.Address[:]) != row.Recovered {
					t.Fatalf("recovered_address = %x (%v), want %s", recovered.Address, err, row.Recovered)
				}
			}
		verify:
			err := Verify(context.Background(), e, opts)
			if row.Expect == "accept" {
				if err != nil {
					t.Fatalf("Verify = %v, want accept", err)
				}
				return
			}
			var want error
			for _, candidate := range sdkErrors {
				if candidate.Error() == row.Error {
					want = candidate
				}
			}
			if want == nil {
				t.Fatalf("unknown wire error %q", row.Error)
			}
			if !errors.Is(err, want) {
				t.Fatalf("Verify = %v, want %s", err, row.Error)
			}
		})
	}
	if seen < 20 {
		t.Fatalf("only %d rows checked; the wire table changed shape", seen)
	}
}
