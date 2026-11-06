package buildersync

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	hubv1 "github.com/TrueOpen/nexus/gen/trueopen/hub/v1"
	nexusv1 "github.com/TrueOpen/nexus/gen/trueopen/nexus/v1"
	"github.com/TrueOpen/nexus/gen/trueopen/nexus/v1/nexusv1connect"
	"github.com/TrueOpen/nexus/internal/chaincli"
)

// endpointTTL is how long a member's resolved endpoint is used before it is read again; a failed
// call reads it again at once.
const endpointTTL = 5 * time.Minute

// participantBuilder is the descriptor participant type of a Builder.
const participantBuilder = "BUILDER"

// DescriptorChain reads Builders' service descriptors.
type DescriptorChain interface {
	QueryBuilder(ctx context.Context, address string) (chaincli.BuilderState, error)
	QueryServiceDescriptor(ctx context.Context, participantType, operatorAddress string, descriptorVersion uint64) (chaincli.ServiceDescriptorState, error)
}

// ChainPeers reaches group members at the NEXUS_GRPC endpoint of their current on-chain service
// descriptor. An https/grpcs endpoint with a tls_pubkey_hash is only trusted with a certificate of
// that public key; one without a hash goes by the system roots.
type ChainPeers struct {
	chain DescriptorChain
	now   func() time.Time
	// httpClient builds the HTTP client and base URL of an endpoint (peerHTTPClient).
	httpClient func(chaincli.ServiceEndpoint) (*http.Client, string, error)

	mu      sync.Mutex
	clients map[string]peerClient
}

type peerClient struct {
	client   nexusv1connect.BuilderSyncServiceClient
	resolved time.Time
}

// NewChainPeers builds ChainPeers over the chain's descriptors.
func NewChainPeers(chain DescriptorChain) *ChainPeers {
	return &ChainPeers{chain: chain, now: time.Now, httpClient: peerHTTPClient, clients: map[string]peerClient{}}
}

// Sync implements Peers.
func (p *ChainPeers) Sync(ctx context.Context, operator string, req *nexusv1.SyncRequest) (*nexusv1.SyncResponse, error) {
	client, err := p.client(ctx, operator)
	if err != nil {
		return nil, err
	}
	resp, err := client.Sync(ctx, connect.NewRequest(req))
	if err != nil && connect.CodeOf(err) != connect.CodeResourceExhausted {
		// A member that only rate-limited the call is reachable where it is.
		p.mu.Lock()
		delete(p.clients, operator)
		p.mu.Unlock()
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (p *ChainPeers) client(ctx context.Context, operator string) (nexusv1connect.BuilderSyncServiceClient, error) {
	p.mu.Lock()
	cached, ok := p.clients[operator]
	p.mu.Unlock()
	if ok && p.now().Sub(cached.resolved) < endpointTTL {
		return cached.client, nil
	}
	endpoint, err := p.endpoint(ctx, operator)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errNoPeer, operator, err)
	}
	httpClient, baseURL, err := p.httpClient(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errNoPeer, operator, err)
	}
	client := nexusv1connect.NewBuilderSyncServiceClient(httpClient, baseURL)
	p.mu.Lock()
	p.clients[operator] = peerClient{client: client, resolved: p.now()}
	p.mu.Unlock()
	return client, nil
}

// endpoint is the member's NEXUS_GRPC endpoint in its current descriptor.
func (p *ChainPeers) endpoint(ctx context.Context, operator string) (chaincli.ServiceEndpoint, error) {
	builder, err := p.chain.QueryBuilder(ctx, operator)
	if err != nil {
		return chaincli.ServiceEndpoint{}, err
	}
	if builder.Address != operator || builder.CurrentDescriptorVersion == 0 {
		return chaincli.ServiceEndpoint{}, errors.New("no current service descriptor")
	}
	descriptor, err := p.chain.QueryServiceDescriptor(ctx, participantBuilder, operator, builder.CurrentDescriptorVersion)
	if err != nil {
		return chaincli.ServiceEndpoint{}, err
	}
	if descriptor.OperatorAddress != operator || descriptor.DescriptorVersion != builder.CurrentDescriptorVersion {
		return chaincli.ServiceEndpoint{}, errors.New("service descriptor is not the Builder's current one")
	}
	for _, e := range descriptor.Endpoints {
		if e.Kind == hubv1.ServiceEndpointKind_SERVICE_ENDPOINT_KIND_NEXUS_GRPC {
			return e, nil
		}
	}
	return chaincli.ServiceEndpoint{}, errors.New("no NEXUS_GRPC endpoint published")
}

// peerHTTPClient is the HTTP client and base URL of an endpoint: plaintext for http, TLS for
// https/grpcs, pinned to the endpoint's public key hash when it has one.
func peerHTTPClient(e chaincli.ServiceEndpoint) (*http.Client, string, error) {
	u, err := url.Parse(e.URI)
	if err != nil || u.Host == "" {
		return nil, "", fmt.Errorf("endpoint %q is not an absolute URL", e.URI)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return &http.Client{}, "http://" + u.Host + strings.TrimRight(u.Path, "/"), nil
	case "https", "grpcs":
	default:
		return nil, "", fmt.Errorf("endpoint scheme %q is not http, https or grpcs", u.Scheme)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin := strings.TrimSpace(e.TLSPubKeyHash); pin != "" {
		want, err := hex.DecodeString(pin)
		if err != nil || len(want) != sha256.Size {
			return nil, "", fmt.Errorf("endpoint tls_pubkey_hash %q is not a sha256", pin)
		}
		// The certificate is self-signed: its identity is the public key the chain names.
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("peer sent no certificate")
			}
			got := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
				return errors.New("peer certificate is not the key its descriptor names")
			}
			return nil
		}
	}
	transport := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}
	return &http.Client{Transport: transport}, "https://" + u.Host + strings.TrimRight(u.Path, "/"), nil
}
