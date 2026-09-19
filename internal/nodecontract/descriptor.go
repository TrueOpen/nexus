package nodecontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	DescriptorSchemaV1    = "trueopen-builder-descriptor-v1"
	BuilderDescriptorPath = "/.well-known/trueopen-builder.json"
)

type BuilderDescriptor struct {
	SchemaVersion   string `json:"schema_version"`
	BuilderAddress  string `json:"builder_address"`
	ServiceEndpoint string `json:"service_endpoint"`
	Moniker         string `json:"moniker"`
	P2PHint         string `json:"p2p_hint"`
}

func (d BuilderDescriptor) Marshal() ([]byte, string, error) {
	if err := d.validate(); err != nil {
		return nil, "", err
	}
	body, err := json.Marshal(d)
	if err != nil {
		return nil, "", fmt.Errorf("builder descriptor: marshal: %w", err)
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

func (d BuilderDescriptor) validate() error {
	if d.SchemaVersion != DescriptorSchemaV1 {
		return fmt.Errorf("builder descriptor: unsupported schema %q", d.SchemaVersion)
	}
	if strings.TrimSpace(d.BuilderAddress) == "" || strings.TrimSpace(d.BuilderAddress) != d.BuilderAddress {
		return fmt.Errorf("builder descriptor: canonical builder address required")
	}
	if _, err := validateHTTPSEndpoint(d.ServiceEndpoint); err != nil {
		return err
	}
	if strings.TrimSpace(d.Moniker) != d.Moniker || strings.TrimSpace(d.P2PHint) != d.P2PHint {
		return fmt.Errorf("builder descriptor: moniker and p2p_hint must be canonical")
	}
	return nil
}

// ParseBuilderDescriptor accepts only the exact V1 canonical JSON encoding.
// Reordered, missing, duplicate, unknown, or whitespace-padded fields fail.
func ParseBuilderDescriptor(body []byte) (BuilderDescriptor, string, error) {
	if len(body) == 0 || !json.Valid(body) {
		return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: invalid json")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: canonical object required")
	}
	want := []string{"schema_version", "builder_address", "service_endpoint", "moniker", "p2p_hint"}
	values := make([]string, len(want))
	for i, name := range want {
		if !decoder.More() {
			return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: missing field %q", name)
		}
		key, err := decoder.Token()
		if err != nil || key != name {
			return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: expected field %q", name)
		}
		if err := decoder.Decode(&values[i]); err != nil {
			return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: field %q must be a string", name)
		}
	}
	if decoder.More() {
		return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: unknown or duplicate field")
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: unterminated object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: trailing data")
	}
	descriptor := BuilderDescriptor{
		SchemaVersion: values[0], BuilderAddress: values[1], ServiceEndpoint: values[2],
		Moniker: values[3], P2PHint: values[4],
	}
	canonical, hash, err := descriptor.Marshal()
	if err != nil {
		return BuilderDescriptor{}, "", err
	}
	if !bytes.Equal(body, canonical) {
		return BuilderDescriptor{}, "", fmt.Errorf("builder descriptor: non-canonical json")
	}
	return descriptor, hash, nil
}

func BuilderDescriptorURI(publicEndpoint string) (string, error) {
	endpoint, err := validateHTTPSEndpoint(publicEndpoint)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(endpoint.String(), "/") + BuilderDescriptorPath, nil
}

func DescriptorHandler(body []byte) http.Handler {
	immutable := append([]byte(nil), body...)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		if r.Method == http.MethodGet {
			_, _ = w.Write(immutable)
		}
	})
}

func validateHTTPSEndpoint(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("builder descriptor: public endpoint must be an absolute https URL")
	}
	return parsed, nil
}
