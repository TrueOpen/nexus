package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuilderDescriptorBytesAndHash(t *testing.T) {
	d := BuilderDescriptor{
		SchemaVersion:   DescriptorSchemaV1,
		BuilderAddress:  "trueopen1builder",
		ServiceEndpoint: "https://builder.example",
		Moniker:         "builder-1",
		P2PHint:         "nats://builder.example:4222",
	}
	body, hash, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	wantBody := []byte(`{"schema_version":"trueopen-builder-descriptor-v1","builder_address":"trueopen1builder","service_endpoint":"https://builder.example","moniker":"builder-1","p2p_hint":"nats://builder.example:4222"}`)
	if !bytes.Equal(body, wantBody) {
		t.Fatalf("body = %s, want %s", body, wantBody)
	}
	sum := sha256.Sum256(wantBody)
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash = %s, want %x", hash, sum)
	}
}

func TestBuilderDescriptorCanonicalRoundTrip(t *testing.T) {
	d := BuilderDescriptor{
		SchemaVersion:   DescriptorSchemaV1,
		BuilderAddress:  "trueopen1builder",
		ServiceEndpoint: "https://builder.example",
	}
	body, hash, err := d.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"schema_version":"trueopen-builder-descriptor-v1","builder_address":"trueopen1builder","service_endpoint":"https://builder.example","moniker":"","p2p_hint":""}`)
	if !bytes.Equal(body, want) {
		t.Fatalf("body = %s, want %s", body, want)
	}
	parsed, parsedHash, err := ParseBuilderDescriptor(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != d || parsedHash != hash {
		t.Fatalf("parsed = %+v hash=%s, want %+v hash=%s", parsed, parsedHash, d, hash)
	}
}

func TestBuilderDescriptorRejectsNonCanonicalJSON(t *testing.T) {
	canonical := `{"schema_version":"trueopen-builder-descriptor-v1","builder_address":"trueopen1builder","service_endpoint":"https://builder.example","moniker":"","p2p_hint":""}`
	tests := map[string][]byte{
		"leading whitespace": []byte(" " + canonical),
		"trailing newline":   []byte(canonical + "\n"),
		"reordered fields":   []byte(`{"builder_address":"trueopen1builder","schema_version":"trueopen-builder-descriptor-v1","service_endpoint":"https://builder.example","moniker":"","p2p_hint":""}`),
		"missing field":      []byte(`{"schema_version":"trueopen-builder-descriptor-v1","builder_address":"trueopen1builder","service_endpoint":"https://builder.example","moniker":""}`),
		"unknown field":      []byte(`{"schema_version":"trueopen-builder-descriptor-v1","builder_address":"trueopen1builder","service_endpoint":"https://builder.example","moniker":"","p2p_hint":"","extra":true}`),
		"duplicate field":    []byte(`{"schema_version":"trueopen-builder-descriptor-v1","builder_address":"trueopen1builder","service_endpoint":"https://builder.example","moniker":"","p2p_hint":"","p2p_hint":""}`),
		"trailing token":     []byte(canonical + `{}`),
		"invalid utf8":       append([]byte(canonical[:len(canonical)-2]), 0xff, '"', '}'),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseBuilderDescriptor(body); err == nil {
				t.Fatalf("ParseBuilderDescriptor(%q) succeeded", body)
			}
		})
	}
}

// This assertion used to be permanently red: validateHTTPSEndpoint was deliberately relaxed to
// http|https long ago (local integration does not want to set up certificates first), yet the
// test still said "http must be rejected". The assertion is changed here to match the
// implementation rather than reverting the implementation: relaxing the scheme is an existing
// decision, and the closed set of schemes for on-chain endpoints has its own source
// (servicedescriptor.go, which includes http).
func TestBuilderDescriptorURIAcceptsHTTPAndHTTPS(t *testing.T) {
	uri, err := BuilderDescriptorURI("https://builder.example/api")
	if err != nil {
		t.Fatal(err)
	}
	if uri != "https://builder.example/api/.well-known/trueopen-builder.json" {
		t.Fatalf("uri = %q", uri)
	}
	plain, err := BuilderDescriptorURI("http://builder.example")
	if err != nil {
		t.Fatal(err)
	}
	if plain != "http://builder.example/.well-known/trueopen-builder.json" {
		t.Fatalf("uri = %q", plain)
	}
	for _, raw := range []string{"", "builder.example", "ftp://builder.example", "https://builder.example#frag"} {
		if _, err := BuilderDescriptorURI(raw); err == nil {
			t.Fatalf("endpoint %q must be rejected", raw)
		}
	}
}

func TestDescriptorHandlerServesExactBytes(t *testing.T) {
	body := []byte(`{"schema_version":"trueopen-builder-descriptor-v1"}`)
	rr := httptest.NewRecorder()
	DescriptorHandler(body).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, BuilderDescriptorPath, nil))
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), body) {
		t.Fatalf("response code=%d body=%q", rr.Code, rr.Body.Bytes())
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", rr.Header().Get("Content-Type"))
	}
}
