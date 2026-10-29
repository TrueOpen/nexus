package buildersync

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

const peerOperator = "builder-m"

// fakeDescriptors serves one Builder and its descriptors, counting the Builder reads.
type fakeDescriptors struct {
	builder     chaincli.BuilderState
	descriptors map[uint64]chaincli.ServiceDescriptorState
	reads       int
}

func (f *fakeDescriptors) QueryBuilder(_ context.Context, address string) (chaincli.BuilderState, error) {
	f.reads++
	if address != f.builder.Address {
		return chaincli.BuilderState{}, errors.New("not found")
	}
	return f.builder, nil
}

func (f *fakeDescriptors) QueryServiceDescriptor(_ context.Context, participantType, operator string, version uint64) (chaincli.ServiceDescriptorState, error) {
	d, ok := f.descriptors[version]
	if !ok || participantType != participantBuilder || operator != f.builder.Address {
		return chaincli.ServiceDescriptorState{}, errors.New("not found")
	}
	return d, nil
}

func grpcEndpoint(uri, pin string) chaincli.ServiceEndpoint {
	return chaincli.ServiceEndpoint{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC, URI: uri, TLSPubKeyHash: pin}
}

func descriptorsWith(endpoints ...chaincli.ServiceEndpoint) *fakeDescriptors {
	return &fakeDescriptors{
		builder: chaincli.BuilderState{Address: peerOperator, CurrentDescriptorVersion: 2},
		descriptors: map[uint64]chaincli.ServiceDescriptorState{
			1: {OperatorAddress: peerOperator, DescriptorVersion: 1, Endpoints: []chaincli.ServiceEndpoint{grpcEndpoint("http://old:9090", "")}},
			2: {OperatorAddress: peerOperator, DescriptorVersion: 2, Endpoints: endpoints},
		},
	}
}

// A member is reached at the NEXUS_GRPC endpoint of its current descriptor, and only there.
func TestPeerEndpointIsTheCurrentNexusGRPC(t *testing.T) {
	other := chaincli.ServiceEndpoint{Kind: hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_UNSPECIFIED, URI: "http://other:1"}
	chain := descriptorsWith(other, grpcEndpoint("http://m:9090", ""))
	got, err := NewChainPeers(chain).endpoint(context.Background(), peerOperator)
	if err != nil || got.URI != "http://m:9090" {
		t.Fatalf("endpoint = %+v, %v", got, err)
	}

	for name, mutate := range map[string]func(*fakeDescriptors){
		"no NEXUS_GRPC endpoint": func(f *fakeDescriptors) {
			d := f.descriptors[2]
			d.Endpoints = []chaincli.ServiceEndpoint{other}
			f.descriptors[2] = d
		},
		"no current descriptor": func(f *fakeDescriptors) { f.builder.CurrentDescriptorVersion = 0 },
		"descriptor of another version": func(f *fakeDescriptors) {
			d := f.descriptors[2]
			d.DescriptorVersion = 1
			f.descriptors[2] = d
		},
		"descriptor of another operator": func(f *fakeDescriptors) {
			d := f.descriptors[2]
			d.OperatorAddress = "builder-x"
			f.descriptors[2] = d
		},
		"Builder read answers another address": func(f *fakeDescriptors) {
			f.builder.Address = "builder-x"
		},
	} {
		t.Run(name, func(t *testing.T) {
			chain := descriptorsWith(other, grpcEndpoint("http://m:9090", ""))
			mutate(chain)
			if got, err := NewChainPeers(chain).endpoint(context.Background(), peerOperator); err == nil {
				t.Fatalf("endpoint = %+v", got)
			}
		})
	}
}

// A resolved member client is used for endpointTTL, then the descriptor is read again.
func TestPeerClientIsResolvedAgainAfterTheTTL(t *testing.T) {
	chain := descriptorsWith(grpcEndpoint("http://m:9090", ""))
	now := time.UnixMilli(1_800_000_000_000)
	p := NewChainPeers(chain)
	p.now = func() time.Time { return now }
	for range 3 {
		if _, err := p.client(context.Background(), peerOperator); err != nil {
			t.Fatal(err)
		}
	}
	if chain.reads != 1 {
		t.Fatalf("descriptor read %d times within the TTL", chain.reads)
	}
	now = now.Add(endpointTTL)
	if _, err := p.client(context.Background(), peerOperator); err != nil || chain.reads != 2 {
		t.Fatalf("after the TTL: reads %d, %v", chain.reads, err)
	}
	if _, err := p.client(context.Background(), "builder-unknown"); !errors.Is(err, errNoPeer) {
		t.Fatalf("unknown member: %v", err)
	}
}

func TestPeerHTTPClientSchemes(t *testing.T) {
	for _, tc := range []struct {
		uri, pin, base string
		ok             bool
	}{
		{"http://m:9090/", "", "http://m:9090", true},
		{"https://m:443/nexus/", "", "https://m:443/nexus", true},
		{"grpcs://m:443", "", "https://m:443", true},
		{"tcp://m:9090", "", "", false},
		{"m:9090", "", "", false},
		{"https://m:443", "zz", "", false},
		{"https://m:443", strings.Repeat("ab", 16), "", false},
	} {
		_, base, err := peerHTTPClient(grpcEndpoint(tc.uri, tc.pin))
		if (err == nil) != tc.ok || base != tc.base {
			t.Fatalf("%s pin %q: base %q, %v", tc.uri, tc.pin, base, err)
		}
	}
}

// A pinned endpoint takes only a certificate of the public key its descriptor names.
func TestPinnedPeerTakesOnlyTheNamedKey(t *testing.T) {
	named, other := selfSigned(t), selfSigned(t)
	pin := sha256.Sum256(named.RawSubjectPublicKeyInfo)
	client, _, err := peerHTTPClient(grpcEndpoint("https://m:443", hex.EncodeToString(pin[:])))
	if err != nil {
		t.Fatal(err)
	}
	verify := client.Transport.(*http.Transport).TLSClientConfig.VerifyConnection
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{named}}); err != nil {
		t.Fatalf("named key refused: %v", err)
	}
	if err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}}); err == nil {
		t.Fatal("another key accepted")
	}
	if err := verify(tls.ConnectionState{}); err == nil {
		t.Fatal("no certificate accepted")
	}

	unpinned, _, err := peerHTTPClient(grpcEndpoint("https://m:443", ""))
	if err != nil {
		t.Fatal(err)
	}
	cfg := unpinned.Transport.(*http.Transport).TLSClientConfig
	if cfg.InsecureSkipVerify || cfg.VerifyConnection != nil {
		t.Fatal("an endpoint without a pin does not go by the system roots")
	}
}

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "m"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
