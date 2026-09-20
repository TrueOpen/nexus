// Package config loads and validates the nexus startup configuration (Implementation Design §3).
// Configuration precedence: defaults < YAML < environment variables < cobra flag; hot reload is not supported.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir        string               `yaml:"data_dir"`
	Log            LogConfig            `yaml:"log"`
	Ingress        IngressConfig        `yaml:"ingress"`
	NATS           NATSConfig           `yaml:"nats"`
	Security       SecurityConfig       `yaml:"security"`
	Chain          ChainConfig          `yaml:"chain"`
	Hub            HubConfig            `yaml:"hub"`
	Identity       IdentityConfig       `yaml:"identity"`
	PayloadStorage PayloadStorageConfig `yaml:"payload_storage"`
	OutputDelivery OutputDeliveryConfig `yaml:"output_delivery"`
	TaskData       TaskDataConfig       `yaml:"task_data"`
	NATSAuth       NATSAuthConfig       `yaml:"natsauth"`
}

type PayloadStorageConfig struct {
	MaxBytes int `yaml:"max_bytes"`
}

type OutputDeliveryConfig struct {
	RequirePlaintextOutput bool          `yaml:"require_plaintext_output"`
	MaxBytes               int           `yaml:"output_max_bytes"`
	PlaintextTTL           time.Duration `yaml:"plaintext_ttl"`
	TombstoneTTL           time.Duration `yaml:"tombstone_ttl"`
	SweepInterval          time.Duration `yaml:"sweep_interval"`
}

type TaskDataConfig struct {
	InlineMaxBytes             uint64        `yaml:"inline_max_bytes"`
	ChunkSizeBytes             uint64        `yaml:"chunk_size_bytes"`
	MaxRangeBytes              uint64        `yaml:"max_range_bytes"`
	MaxBlobBytes               uint64        `yaml:"max_blob_bytes"`
	SpoolReservationBytes      uint64        `yaml:"spool_reservation_bytes"`
	DiskAcceptWatermarkPercent uint32        `yaml:"disk_accept_watermark_percent"`
	RequestTTLBlocks           uint64        `yaml:"request_ttl_blocks"`
	RetentionLeaseBlocks       uint64        `yaml:"retention_lease_blocks"`
	SweepInterval              time.Duration `yaml:"sweep_interval"`
	// OutputStream is the ADR-0017 streaming OUTPUT data plane (Streaming Output Delivery Design §6).
	OutputStream OutputStreamConfig `yaml:"output_stream"`
}

// OutputStreamConfig covers streaming OUTPUT upload and subscription. Enabled by default: Cortex
// delivers OUTPUT only over this stream. When Enabled is false, UploadTaskOutputStream and the
// streaming SubscribeOutput / AckOutput return Unimplemented — no OUTPUT can be uploaded at all.
//
// The limits that decide whether a stream is valid must be identical across every Nexus in the
// network (configured from the deployment baseline until the on-chain parameters land): the first
// three fields of this struct plus task_data.chunk_size_bytes, which is also the per-frame text limit.
// Differing chunk_size_bytes means the same frame is accepted by one node and rejected by another,
// and Verifiers can then no longer fetch the complete data.
// SubscriberBufferFrames only affects local subscribers and may differ per node.
type OutputStreamConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxOutputMMRLeaves is the maximum frame count (parameter table max_output_mmr_leaves, localnet placeholder 65536).
	MaxOutputMMRLeaves uint64 `yaml:"max_output_mmr_leaves"`
	// MinFrameBytes is the minimum bytes per frame, except for the last frame (parameter table min_output_stream_frame_bytes, localnet placeholder 16).
	MinFrameBytes uint64 `yaml:"min_output_stream_frame_bytes"`
	// MaxAttachmentBytes is the per-frame attachment limit; 0 means attachments are rejected (must be identical across Nexus instances until the protocol settles it).
	MaxAttachmentBytes uint64 `yaml:"max_attachment_bytes"`
	// SubscriberBufferFrames is the buffered frame count per subscriber; subscribers that fall behind are disconnected.
	SubscriberBufferFrames uint32 `yaml:"subscriber_buffer_frames"`
}

func (c OutputStreamConfig) Validate(chunkSize uint64) error {
	if !c.Enabled {
		return nil
	}
	switch {
	case c.MaxOutputMMRLeaves == 0:
		return fmt.Errorf("task_data.output_stream max_output_mmr_leaves must be positive")
	case c.MinFrameBytes > chunkSize:
		return fmt.Errorf("task_data.output_stream min_output_stream_frame_bytes must not exceed chunk_size_bytes")
	case c.SubscriberBufferFrames == 0:
		return fmt.Errorf("task_data.output_stream subscriber_buffer_frames must be positive")
	default:
		return nil
	}
}

func (c TaskDataConfig) Validate() error {
	switch {
	case c.InlineMaxBytes == 0 || c.ChunkSizeBytes == 0 || c.MaxRangeBytes == 0 ||
		c.MaxBlobBytes == 0 || c.SpoolReservationBytes == 0:
		return fmt.Errorf("task_data byte limits must be positive")
	case c.ChunkSizeBytes > c.MaxRangeBytes:
		return fmt.Errorf("task_data chunk_size_bytes must not exceed max_range_bytes")
	case c.MaxRangeBytes > c.MaxBlobBytes:
		return fmt.Errorf("task_data max_range_bytes must not exceed max_blob_bytes")
	case c.InlineMaxBytes > c.MaxBlobBytes:
		return fmt.Errorf("task_data inline_max_bytes must not exceed max_blob_bytes")
	case c.SpoolReservationBytes < c.MaxBlobBytes:
		return fmt.Errorf("task_data spool_reservation_bytes must cover max_blob_bytes")
	case c.DiskAcceptWatermarkPercent == 0 || c.DiskAcceptWatermarkPercent >= 100:
		return fmt.Errorf("task_data disk_accept_watermark_percent must be between 1 and 99")
	case c.RequestTTLBlocks == 0 || c.RetentionLeaseBlocks == 0:
		return fmt.Errorf("task_data request TTL and retention lease blocks must be positive")
	case c.SweepInterval <= 0:
		return fmt.Errorf("task_data sweep_interval must be positive")
	default:
		return c.OutputStream.Validate(c.ChunkSizeBytes)
	}
}

// IdentityConfig is this node's own Builder identity (Implementation Design §3).
// Used by the coordinator self-check (whether this node is in the active set) and the per-order rank computation.
type IdentityConfig struct {
	BuilderAddress string `yaml:"builder_address"` // this node's on-chain builder address (bech32); empty = identity not configured
	Bech32Prefix   string `yaml:"bech32_prefix"`   // account address prefix (default "trueopen"), used to derive the signer address

	KeystoreFile                string `yaml:"keystore_file"`          // path to a Cosmos SDK keys export armor file (production signing entry point)
	KeystorePassword            string `yaml:"keystore_password"`      // keystore passphrase (recommended for dev only; use PasswordFile in production)
	KeystorePasswordFile        string `yaml:"keystore_password_file"` // keystore passphrase file
	PrivateKey                  string `yaml:"private_key"`            // Cosmos armor or --unsafe --unarmored-hex private key content
	PrivateKeyHex               string `yaml:"private_key_hex"`        // legacy config compatibility: 32-byte secp256k1 private key hex
	PrivateKeyFile              string `yaml:"private_key_file"`       // Cosmos armor or --unsafe --unarmored-hex private key file
	ServiceKeystoreFile         string `yaml:"service_keystore_file"`
	ServiceKeystorePassword     string `yaml:"service_keystore_password"`
	ServiceKeystorePasswordFile string `yaml:"service_keystore_password_file"`

	PublicEndpoint string `yaml:"public_endpoint"` // the public nexus endpoint registered on chain, e.g. https://builder.example:8080
	Moniker        string `yaml:"moniker"`
	P2PHint        string `yaml:"p2p_hint"`

	// ServiceEndpoints is the ServiceDescriptorV1.endpoints submitted on chain (§9.6b).
	// When left empty, three entries are derived from PublicEndpoint (see builderreg.ServiceEndpoints),
	// so older deployments that only configured public_endpoint can upgrade without config changes.
	ServiceEndpoints []ServiceEndpointConfig `yaml:"service_endpoints"`

	// Deprecated: the frozen-contract on-chain descriptor no longer has an effective/expires height;
	// without a validity period a descriptor has no renewal window, so these two fields no longer take
	// part in any decision. They are kept only so existing nexus.yaml files still pass strict YAML
	// validation, and will be removed in the next breaking config version.
	DescriptorValidityBlocks    uint64 `yaml:"descriptor_validity_blocks"`
	DescriptorRenewBeforeBlocks uint64 `yaml:"descriptor_renew_before_blocks"`
}

// ServiceEndpointConfig is one on-chain service endpoint. Kind takes a short name from the closed three-value enum of §9.6b:
// NEXUS_GRPC / OBJECT_GATEWAY_HTTPS / HEALTH_HTTPS.
type ServiceEndpointConfig struct {
	Kind            string `yaml:"kind"`
	URI             string `yaml:"uri"`
	ProtocolVersion string `yaml:"protocol_version"` // empty takes "v1"
	TLSPubKeyHash   string `yaml:"tls_pubkey_hash"`  // optional; 64 lowercase hex characters, must not be all zero
}

type LogConfig struct {
	Level      string `yaml:"level"`        // debug/info/warn/error
	Format     string `yaml:"format"`       // text | json
	File       string `yaml:"file"`         // empty = stdout only; non-empty = also write to a file and rotate it
	MaxSizeMB  int    `yaml:"max_size_mb"`  // per-file limit, rotate once exceeded
	MaxBackups int    `yaml:"max_backups"`  // number of old files kept
	MaxAgeDays int    `yaml:"max_age_days"` // days old files are kept
	Compress   bool   `yaml:"compress"`     // gzip rotated files
}

type IngressConfig struct {
	ListenAddr  string   `yaml:"listen_addr"`  // public :8080 (Connect: gRPC + gRPC-Web + HTTP/JSON + /healthz)
	APIKeys     []string `yaml:"api_keys"`     // list of valid api-keys; empty = no check
	IPWhitelist []string `yaml:"ip_whitelist"` // allowed IPs / CIDRs; empty = unrestricted
	// RequireSDKEnvelope true = every SDK request must carry a valid SDKRequestEnvelopeV1 (production);
	// false = lenient (devnet): if one is present it must verify, if absent the request passes.
	RequireSDKEnvelope bool `yaml:"require_sdk_envelope"`
	// TLS lets ingress terminate TLS itself (HTTP/2 over TLS) instead of depending on a front proxy.
	TLS IngressTLSConfig `yaml:"tls"`
}

// IngressTLSConfig is the TLS listener configuration of ingress.
//
// Enabled=false (default): plaintext h2c, behaviour exactly as before, for local integration.
// Enabled=true without certificates: the first start generates a self-signed certificate under
// <data_dir>/tls/ and reuses it afterwards; the sha256 of the certificate public key is written into
// the on-chain service descriptor as tls_pubkey_hash and clients check the server identity against it,
// so a Builder does not need a certificate from a certificate authority.
// Enabled=true with certificates: the given PEM files are used (relative paths resolve against the
// directory holding the YAML file).
type IngressTLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"` // PEM certificate chain; paired with key_file
	KeyFile  string `yaml:"key_file"`  // PEM private key; paired with cert_file
}

// Validate only checks field combinations: certificate and private key must be set together, and when
// disabled no certificate path may be left behind, otherwise operators would believe TLS is already on.
func (c IngressTLSConfig) Validate() error {
	hasCert, hasKey := strings.TrimSpace(c.CertFile) != "", strings.TrimSpace(c.KeyFile) != ""
	switch {
	case hasCert != hasKey:
		return fmt.Errorf("ingress.tls: cert_file and key_file must be set together")
	case !c.Enabled && (hasCert || hasKey):
		return fmt.Errorf("ingress.tls: cert_file/key_file are set but enabled=false; set enabled=true or remove them")
	}
	return nil
}

// ValidateTransport checks that the listener mode and the public address agree: when ingress terminates
// TLS itself, the on-chain descriptor must not point clients at plaintext http.
func (c Config) ValidateTransport() error {
	if err := c.Ingress.TLS.Validate(); err != nil {
		return err
	}
	endpoint := strings.TrimSpace(c.Identity.PublicEndpoint)
	if !c.Ingress.TLS.Enabled || endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("identity.public_endpoint %q: %w", endpoint, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "grpcs":
		return nil
	default:
		return fmt.Errorf("identity.public_endpoint %q must use https when ingress.tls.enabled=true", endpoint)
	}
}

type NATSConfig struct {
	Servers  []string `yaml:"servers"`  // NATS servers to connect to (local/nearby + fallbacks); empty = stub mode; use tls:// in production
	User     string   `yaml:"user"`     // NATS username (dev only; rejected in production mode)
	Password string   `yaml:"password"` // NATS password (dev only; rejected in production mode)
	// ADR-0016 transition state: PEM file of the server certificate (or of the CA that issued it); with
	// tls:// the server is verified against it, and without it the system root certificates are used.
	// CredsFile is the NATS creds (user JWT + nkey seed) that replaces username and password.
	CAFile    string `yaml:"ca_file"`
	CredsFile string `yaml:"creds_file"`
	// SentinelFile is the bearer user JWT file of the AUTH account. It is **public, non-secret data**, not a
	// credential: bearer, without any permission, used only to satisfy the operator-mode precondition
	// that "CONNECT must carry a user JWT for the auth callout to run". ingress hands it to Cortex over
	// GET /v1/nats/sentinel, which removes the need for manual distribution.
	// Empty = the route is not served.
	SentinelFile string `yaml:"sentinel_file"`
}

// TLS reports whether any server is connected over tls://.
func (n NATSConfig) TLS() bool {
	for _, server := range n.Servers {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(server)), "tls://") {
			return true
		}
	}
	return false
}

// SecurityMode is the deployment security baseline switch (monorepo Deployment Security Baseline).
type SecurityMode string

const (
	// SecurityDev performs no hardening checks; behaviour is the same as before the switch existed, for local integration.
	SecurityDev SecurityMode = "dev"
	// SecurityProduction rejects plaintext bus and chain connections, inline private keys and passphrases in the config, and ingress without TLS.
	SecurityProduction SecurityMode = "production"
)

type SecurityConfig struct {
	Mode SecurityMode `yaml:"mode"` // dev | production, defaults to dev
}

// ValidateSecurity checks the configuration according to security.mode. dev only validates the value;
// production rejects item by item:
//   - nats.servers must all be tls://, must not carry user/password, and must provide creds_file and ca_file
//     (in the ADR-0016 transition state the server is verified against the distributed certificate file,
//     with no fallback to the system root certificates);
//   - chain.grpc_addr / hub.grpc_addr must be https:// or grpcs:// unless they are loopback addresses;
//   - identity must not carry private_key_hex / private_key / keystore_password / service_keystore_password,
//     private keys and passphrases always go through files;
//   - ingress.tls.enabled must be true.
func (c Config) ValidateSecurity() error {
	switch c.Security.Mode {
	case "", SecurityDev: // no security block = dev, behaviour unchanged
		return nil
	case SecurityProduction:
	default:
		return fmt.Errorf("security.mode %q is not one of dev, production", c.Security.Mode)
	}
	var problems []string
	if len(c.NATS.Servers) > 0 {
		for _, server := range c.NATS.Servers {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(server)), "tls://") {
				problems = append(problems, fmt.Sprintf("nats.servers %q must use tls:// in production", server))
			}
		}
		if c.NATS.User != "" || c.NATS.Password != "" {
			problems = append(problems, "nats.user / nats.password are not allowed in production; use nats.creds_file")
		}
		if strings.TrimSpace(c.NATS.CredsFile) == "" {
			problems = append(problems, "nats.creds_file is required in production")
		}
		if strings.TrimSpace(c.NATS.CAFile) == "" {
			problems = append(problems, "nats.ca_file is required in production: verify the server against the distributed certificate, not the system roots (ADR-0016)")
		}
	}
	// sentinel is optional, but once configured the file must really exist: ingress fails closed and
	// refuses to start, so saying so during config validation beats failing halfway through startup.
	if path := strings.TrimSpace(c.NATS.SentinelFile); path != "" {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			problems = append(problems, fmt.Sprintf("nats.sentinel_file %q must be an existing regular file", path))
		}
	}
	if err := requireTLSUnlessLoopback("chain.grpc_addr", c.Chain.GRPCAddr); err != nil {
		problems = append(problems, err.Error())
	}
	if c.Hub.Enabled {
		if err := requireTLSUnlessLoopback("hub.grpc_addr", c.Hub.GRPCAddr); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if strings.TrimSpace(c.Identity.PrivateKeyHex) != "" {
		problems = append(problems, "identity.private_key_hex is not allowed in production; use keystore_file + keystore_password_file")
	}
	if strings.TrimSpace(c.Identity.PrivateKey) != "" {
		problems = append(problems, "identity.private_key is not allowed in production; use private_key_file or keystore_file")
	}
	if c.Identity.KeystorePassword != "" {
		problems = append(problems, "identity.keystore_password is not allowed in production; use keystore_password_file")
	}
	if c.Identity.ServiceKeystorePassword != "" {
		problems = append(problems, "identity.service_keystore_password is not allowed in production; use service_keystore_password_file")
	}
	if !c.Ingress.TLS.Enabled {
		problems = append(problems, "ingress.tls.enabled must be true in production (ADR-0015)")
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("security.mode=production: %s", strings.Join(problems, "; "))
}

// requireTLSUnlessLoopback: once the node port runs TLS per the deployment security baseline, clients
// write https://; plaintext over loopback on the same host as node is a deployment choice and is allowed.
func requireTLSUnlessLoopback(field, addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	lower := strings.ToLower(addr)
	if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "grpcs://") {
		return nil
	}
	host := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(lower, "http://"), "grpc://"), "tcp://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.") {
		return nil
	}
	return fmt.Errorf("%s %q must use https:// (or grpcs://) in production unless it is a loopback address", field, addr)
}

// NATSAuthConfig is the configuration of the `nexus natsauth` subcommand (Interface & Topic Catalogue §5.14.5).
// The callout service runs on the same host as NATS and is operated by whoever runs NATS; it connects to
// NATS with the AUTH account creds, signs user JWTs with the signing key of the application account (TRUEOPEN,
// where Cortex users share the account with nexus), and signs responses with the AUTH account signing key.
// None of the three keys ever leaves the host.
type NATSAuthConfig struct {
	// NATS is the callout service's own connection to NATS (AUTH account): servers must be tls://, and creds_file and ca_file are required.
	NATS NATSConfig `yaml:"nats"`
	// CortexAccountPublicKey is the public key of the application account (TRUEOPEN) that Cortex users land in
	// (nkey text starting with A), written into the aud of the user JWT.
	// Validate only does a coarse length/prefix screen (to catch typos); real nkey validity is checked when the natsauth subcommand loads it.
	CortexAccountPublicKey string `yaml:"cortex_account_public_key"`
	// CortexAccountSigningKeyFile is the seed file of that application account's (TRUEOPEN) signing key (nsc generate nkey --account).
	CortexAccountSigningKeyFile string `yaml:"cortex_account_signing_key_file"`
	// AuthAccountSigningKeyFile is the seed file of the AUTH account signing key, used to sign response JWTs.
	AuthAccountSigningKeyFile string `yaml:"auth_account_signing_key_file"`
	// UserJWTTTLMS is the validity of issued user JWTs, ≤ 3,600,000.
	UserJWTTTLMS uint64 `yaml:"user_jwt_ttl_ms"`
	// ChainQueryCacheTTLMS is how long successful chain query results are cached, ≤ 60,000.
	ChainQueryCacheTTLMS uint64 `yaml:"chain_query_cache_ttl_ms"`
	// MaxClockSkewMS is the tolerance for accepting an issued_at_unix_ms later than the local clock.
	MaxClockSkewMS uint64 `yaml:"max_clock_skew_ms"`
	// XKeyFile is optional: the AUTH account curve key seed file, which enables response encryption; empty = no encryption.
	XKeyFile string `yaml:"xkey_file"`
}

const (
	MaxNATSAuthUserJWTTTLMS         uint64 = 3_600_000
	MaxNATSAuthChainQueryCacheTTLMS uint64 = 60_000
	// MaxNATSAuthClockSkewMS: §5.14.5 itself gives no upper bound; this is a local backstop that keeps a
	// mistyped astronomical value from disabling the expiry check. 0 is valid (no skew tolerated at all);
	// only values above the bound are rejected.
	MaxNATSAuthClockSkewMS uint64 = 3_600_000
)

// Validate checks against §5.14.5; anything missing is rejected, nothing is defaulted through.
func (c NATSAuthConfig) Validate() error {
	var problems []string
	if len(c.NATS.Servers) == 0 {
		problems = append(problems, "natsauth.nats.servers is required")
	}
	for _, server := range c.NATS.Servers {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(server)), "tls://") {
			problems = append(problems, fmt.Sprintf("natsauth.nats.servers %q must use tls://", server))
		}
	}
	if c.NATS.User != "" || c.NATS.Password != "" {
		problems = append(problems, "natsauth.nats.user / natsauth.nats.password are not allowed; use natsauth.nats.creds_file")
	}
	if !isAccountPublicKey(c.CortexAccountPublicKey) {
		problems = append(problems, "natsauth.cortex_account_public_key must be an account nkey public key (56 characters starting with A)")
	}
	// All file-valued fields go through one stat check: required ones are first checked for emptiness, then
	// all of them are required to exist and be regular files; xkey_file is optional and only checked when non-empty.
	requiredFiles := []struct {
		name string
		path string
	}{
		{"natsauth.nats.creds_file", c.NATS.CredsFile},
		{"natsauth.nats.ca_file", c.NATS.CAFile},
		{"natsauth.cortex_account_signing_key_file", c.CortexAccountSigningKeyFile},
		{"natsauth.auth_account_signing_key_file", c.AuthAccountSigningKeyFile},
	}
	for _, f := range requiredFiles {
		if strings.TrimSpace(f.path) == "" {
			problems = append(problems, f.name+" is required")
			continue
		}
		if problem := statRegularFile(f.name, f.path); problem != "" {
			problems = append(problems, problem)
		}
	}
	if strings.TrimSpace(c.XKeyFile) != "" {
		if problem := statRegularFile("natsauth.xkey_file", c.XKeyFile); problem != "" {
			problems = append(problems, problem)
		}
	}
	if c.UserJWTTTLMS == 0 || c.UserJWTTTLMS > MaxNATSAuthUserJWTTTLMS {
		problems = append(problems, fmt.Sprintf("natsauth.user_jwt_ttl_ms must be 1..%d", MaxNATSAuthUserJWTTTLMS))
	}
	if c.ChainQueryCacheTTLMS > MaxNATSAuthChainQueryCacheTTLMS {
		problems = append(problems, fmt.Sprintf("natsauth.chain_query_cache_ttl_ms must be 0..%d", MaxNATSAuthChainQueryCacheTTLMS))
	}
	if c.MaxClockSkewMS > MaxNATSAuthClockSkewMS {
		problems = append(problems, fmt.Sprintf("natsauth.max_clock_skew_ms must be 0..%d", MaxNATSAuthClockSkewMS))
	}
	if len(problems) > 0 {
		return fmt.Errorf("natsauth config: %s", strings.Join(problems, "; "))
	}
	return nil
}

// statRegularFile validates that path exists and is a regular file (directories/devices are rejected); field is the error prefix.
func statRegularFile(field, path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("%s: %v", field, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Sprintf("%s: %s is not a regular file", field, path)
	}
	return ""
}

// isAccountPublicKey only does a coarse length/prefix screen (typo guard), not a full nkey validation:
// real validity is checked when the natsauth subcommand loads the nkey.
func isAccountPublicKey(text string) bool {
	text = strings.TrimSpace(text)
	return len(text) == 56 && strings.HasPrefix(text, "A")
}

type ChainConfig struct {
	GRPCAddr string `yaml:"grpc_addr"` // local node gRPC :9090
	ChainID  string `yaml:"chain_id"`

	// Transaction envelope parameters (used when signing and broadcasting).
	GasLimit  uint64 `yaml:"gas_limit"`  // gas limit per Tx (fixed value until gas estimation is wired in)
	FeeDenom  string `yaml:"fee_denom"`  // fee denom; empty = no fee (zero-fee devnet)
	FeeAmount string `yaml:"fee_amount"` // fee amount (big integer as string)

	// DeadlineSweep decides whether this Builder actively submits MsgSweepDeadline.
	DeadlineSweep DeadlineSweepConfig `yaml:"deadline_sweep"`
}

// DeadlineSweepConfig controls the public deadline runner (Keeper Interface Contract §9.6a).
//
// MsgSweepDeadline can be submitted by any account and the runner pays its own gas, so this is an
// operational choice rather than a protocol obligation: disabled by default, with Nexus only observing
// DEADLINE_SWEPT events. Once enabled, Nexus only sweeps verify-stage deadlines whose height the chain
// itself stated, and only for tasks it is already tracking, never indiscriminately across the network.
type DeadlineSweepConfig struct {
	Enabled bool `yaml:"enabled"`
	// GraceBlocks is the grace period in blocks after a deadline expires during which others (including
	// EndBlock) get to sweep first.
	// 0 means sweeping as soon as it expires, which makes multi-Builder deployments collide at the same
	// height; staggering by rank is recommended.
	GraceBlocks uint64 `yaml:"grace_blocks"`
}

// HubConfig is the configuration of the registry chain for network-wide shared state. Enabled=false keeps single-chain compatibility mode only.
type HubConfig struct {
	Enabled   bool   `yaml:"enabled"`
	GRPCAddr  string `yaml:"grpc_addr"`
	ChainID   string `yaml:"chain_id"`
	GasLimit  uint64 `yaml:"gas_limit"`
	FeeDenom  string `yaml:"fee_denom"`
	FeeAmount string `yaml:"fee_amount"`
}

type AuthorityMode string

const (
	AuthorityHub           AuthorityMode = "hub"
	AuthorityCompatibility AuthorityMode = "single-chain-compatibility"
)

// BuilderAuthority is the single target chain for Builder identity, stake and unbond transactions.
type BuilderAuthority struct {
	Mode          AuthorityMode
	Chain         ChainConfig
	LegacyChainID string
}

// BuilderAuthority returns the registry chain for global Builder state. Once Hub is enabled a
// configuration error must fail explicitly; silently falling back to the Task Chain is forbidden.
func (c Config) BuilderAuthority() (BuilderAuthority, error) {
	if !c.Hub.Enabled {
		return BuilderAuthority{
			Mode:          AuthorityCompatibility,
			Chain:         c.Chain,
			LegacyChainID: c.Chain.ChainID,
		}, nil
	}
	if strings.TrimSpace(c.Hub.GRPCAddr) == "" || strings.TrimSpace(c.Hub.ChainID) == "" {
		return BuilderAuthority{}, fmt.Errorf("enabled hub requires grpc_addr and chain_id")
	}
	return BuilderAuthority{
		Mode:          AuthorityHub,
		LegacyChainID: c.Chain.ChainID,
		Chain: ChainConfig{
			GRPCAddr:  c.Hub.GRPCAddr,
			ChainID:   c.Hub.ChainID,
			GasLimit:  c.Hub.GasLimit,
			FeeDenom:  c.Hub.FeeDenom,
			FeeAmount: c.Hub.FeeAmount,
		},
	}, nil
}

// Load reads the configuration from defaults and environment variables, for compatibility callers that do not select a YAML file.
func Load() Config {
	cfg := defaults()
	applyEnv(&cfg)
	return cfg
}

func defaults() Config {
	return Config{
		DataDir:  "./data",
		Security: SecurityConfig{Mode: SecurityDev},
		Log: LogConfig{
			Level:      "info",
			Format:     "text",
			MaxSizeMB:  100,
			MaxBackups: 7,
			MaxAgeDays: 28,
			Compress:   true,
		},
		Ingress: IngressConfig{
			ListenAddr: ":8080",
		},
		PayloadStorage: PayloadStorageConfig{MaxBytes: 16 << 20},
		OutputDelivery: OutputDeliveryConfig{
			MaxBytes:      1 << 20,
			PlaintextTTL:  4 * time.Hour,
			TombstoneTTL:  24 * time.Hour,
			SweepInterval: time.Minute,
		},
		TaskData: TaskDataConfig{
			InlineMaxBytes:             1 << 20,
			ChunkSizeBytes:             256 << 10,
			MaxRangeBytes:              8 << 20,
			MaxBlobBytes:               1 << 30,
			SpoolReservationBytes:      4 << 30,
			DiskAcceptWatermarkPercent: 85,
			RequestTTLBlocks:           20,
			RetentionLeaseBlocks:       1000,
			SweepInterval:              time.Minute,
			OutputStream: OutputStreamConfig{
				Enabled: true, MaxOutputMMRLeaves: 65536, MinFrameBytes: 16, MaxAttachmentBytes: 65536, SubscriberBufferFrames: 256,
			},
		},
		Chain: ChainConfig{
			GRPCAddr: "localhost:9090",
			ChainID:  "trueopen-localnet-1",
			GasLimit: 200000,
		},
		Hub: HubConfig{
			GasLimit: 200000,
		},
		Identity: IdentityConfig{
			Bech32Prefix:                "trueopen",
			DescriptorValidityBlocks:    100000,
			DescriptorRenewBeforeBlocks: 10000,
		},
		// UserJWTTTLMS / ChainQueryCacheTTLMS default to the upper bounds from §5.14.5,
		// because the spec text reads "default 3,600,000 / default 60,000" (the default is the bound).
		NATSAuth: NATSAuthConfig{UserJWTTTLMS: MaxNATSAuthUserJWTTTLMS, ChainQueryCacheTTLMS: MaxNATSAuthChainQueryCacheTTLMS, MaxClockSkewMS: 300_000},
	}
}

func applyEnv(cfg *Config) {
	cfg.DataDir = env("NEXUS_DATA_DIR", cfg.DataDir)
	cfg.Log.Level = env("NEXUS_LOG_LEVEL", cfg.Log.Level)
	cfg.Log.Format = env("NEXUS_LOG_FORMAT", cfg.Log.Format)
	cfg.Log.File = env("NEXUS_LOG_FILE", cfg.Log.File)
	cfg.Log.MaxSizeMB = envInt("NEXUS_LOG_MAX_SIZE_MB", cfg.Log.MaxSizeMB)
	cfg.Log.MaxBackups = envInt("NEXUS_LOG_MAX_BACKUPS", cfg.Log.MaxBackups)
	cfg.Log.MaxAgeDays = envInt("NEXUS_LOG_MAX_AGE_DAYS", cfg.Log.MaxAgeDays)
	cfg.Log.Compress = envBool("NEXUS_LOG_COMPRESS", cfg.Log.Compress)
	cfg.Ingress.ListenAddr = env("NEXUS_INGRESS_ADDR", cfg.Ingress.ListenAddr)
	cfg.Ingress.RequireSDKEnvelope = envBool("NEXUS_REQUIRE_SDK_ENVELOPE", cfg.Ingress.RequireSDKEnvelope)
	cfg.Ingress.TLS.Enabled = envBool("NEXUS_INGRESS_TLS_ENABLED", cfg.Ingress.TLS.Enabled)
	cfg.Ingress.TLS.CertFile = env("NEXUS_INGRESS_TLS_CERT_FILE", cfg.Ingress.TLS.CertFile)
	cfg.Ingress.TLS.KeyFile = env("NEXUS_INGRESS_TLS_KEY_FILE", cfg.Ingress.TLS.KeyFile)
	cfg.PayloadStorage.MaxBytes = envInt("NEXUS_PAYLOAD_MAX_BYTES", cfg.PayloadStorage.MaxBytes)
	cfg.OutputDelivery.RequirePlaintextOutput = envBool("NEXUS_OUTPUT_REQUIRE_PLAINTEXT", cfg.OutputDelivery.RequirePlaintextOutput)
	cfg.OutputDelivery.MaxBytes = envInt("NEXUS_OUTPUT_MAX_BYTES", cfg.OutputDelivery.MaxBytes)
	cfg.OutputDelivery.PlaintextTTL = envDuration("NEXUS_OUTPUT_PLAINTEXT_TTL", cfg.OutputDelivery.PlaintextTTL)
	cfg.OutputDelivery.TombstoneTTL = envDuration("NEXUS_OUTPUT_TOMBSTONE_TTL", cfg.OutputDelivery.TombstoneTTL)
	cfg.OutputDelivery.SweepInterval = envDuration("NEXUS_OUTPUT_SWEEP_INTERVAL", cfg.OutputDelivery.SweepInterval)
	cfg.TaskData.InlineMaxBytes = envUint64("NEXUS_TASK_DATA_INLINE_MAX_BYTES", cfg.TaskData.InlineMaxBytes)
	cfg.TaskData.ChunkSizeBytes = envUint64("NEXUS_TASK_DATA_CHUNK_SIZE_BYTES", cfg.TaskData.ChunkSizeBytes)
	cfg.TaskData.MaxRangeBytes = envUint64("NEXUS_TASK_DATA_MAX_RANGE_BYTES", cfg.TaskData.MaxRangeBytes)
	cfg.TaskData.MaxBlobBytes = envUint64("NEXUS_TASK_DATA_MAX_BLOB_BYTES", cfg.TaskData.MaxBlobBytes)
	cfg.TaskData.SpoolReservationBytes = envUint64("NEXUS_TASK_DATA_SPOOL_RESERVATION_BYTES", cfg.TaskData.SpoolReservationBytes)
	cfg.TaskData.DiskAcceptWatermarkPercent = envUint32("NEXUS_TASK_DATA_DISK_ACCEPT_WATERMARK_PERCENT", cfg.TaskData.DiskAcceptWatermarkPercent)
	cfg.TaskData.RequestTTLBlocks = envUint64("NEXUS_TASK_DATA_REQUEST_TTL_BLOCKS", cfg.TaskData.RequestTTLBlocks)
	cfg.TaskData.RetentionLeaseBlocks = envUint64("NEXUS_TASK_DATA_RETENTION_LEASE_BLOCKS", cfg.TaskData.RetentionLeaseBlocks)
	cfg.TaskData.SweepInterval = envDuration("NEXUS_TASK_DATA_SWEEP_INTERVAL", cfg.TaskData.SweepInterval)
	cfg.TaskData.OutputStream.Enabled = envBool("NEXUS_TASK_DATA_OUTPUT_STREAM_ENABLED", cfg.TaskData.OutputStream.Enabled)
	cfg.TaskData.OutputStream.MaxOutputMMRLeaves = envUint64("NEXUS_TASK_DATA_OUTPUT_STREAM_MAX_LEAVES", cfg.TaskData.OutputStream.MaxOutputMMRLeaves)
	cfg.TaskData.OutputStream.MinFrameBytes = envUint64("NEXUS_TASK_DATA_OUTPUT_STREAM_MIN_FRAME_BYTES", cfg.TaskData.OutputStream.MinFrameBytes)
	cfg.TaskData.OutputStream.MaxAttachmentBytes = envUint64("NEXUS_TASK_DATA_OUTPUT_STREAM_MAX_ATTACHMENT_BYTES", cfg.TaskData.OutputStream.MaxAttachmentBytes)
	cfg.TaskData.OutputStream.SubscriberBufferFrames = envUint32("NEXUS_TASK_DATA_OUTPUT_STREAM_SUBSCRIBER_BUFFER_FRAMES", cfg.TaskData.OutputStream.SubscriberBufferFrames)
	if value, ok := nonEmptyEnv("NEXUS_API_KEYS"); ok {
		cfg.Ingress.APIKeys = splitNonEmpty(value)
	}
	if value, ok := nonEmptyEnv("NEXUS_IP_WHITELIST"); ok {
		cfg.Ingress.IPWhitelist = splitNonEmpty(value)
	}
	if value, ok := nonEmptyEnv("NEXUS_NATS_SERVERS"); ok {
		cfg.NATS.Servers = splitNonEmpty(value)
	}
	cfg.NATS.User = env("NEXUS_NATS_USER", cfg.NATS.User)
	cfg.NATS.Password = env("NEXUS_NATS_PASSWORD", cfg.NATS.Password)
	cfg.NATS.CAFile = env("NEXUS_NATS_CA_FILE", cfg.NATS.CAFile)
	cfg.NATS.CredsFile = env("NEXUS_NATS_CREDS_FILE", cfg.NATS.CredsFile)
	cfg.NATS.SentinelFile = env("NEXUS_NATS_SENTINEL_FILE", cfg.NATS.SentinelFile)
	if value, ok := nonEmptyEnv("NEXUS_NATSAUTH_NATS_SERVERS"); ok {
		cfg.NATSAuth.NATS.Servers = splitNonEmpty(value)
	}
	cfg.NATSAuth.NATS.CAFile = env("NEXUS_NATSAUTH_NATS_CA_FILE", cfg.NATSAuth.NATS.CAFile)
	cfg.NATSAuth.NATS.CredsFile = env("NEXUS_NATSAUTH_NATS_CREDS_FILE", cfg.NATSAuth.NATS.CredsFile)
	cfg.NATSAuth.CortexAccountPublicKey = env("NEXUS_NATSAUTH_CORTEX_ACCOUNT_PUBLIC_KEY", cfg.NATSAuth.CortexAccountPublicKey)
	cfg.NATSAuth.CortexAccountSigningKeyFile = env("NEXUS_NATSAUTH_CORTEX_ACCOUNT_SIGNING_KEY_FILE", cfg.NATSAuth.CortexAccountSigningKeyFile)
	cfg.NATSAuth.AuthAccountSigningKeyFile = env("NEXUS_NATSAUTH_AUTH_ACCOUNT_SIGNING_KEY_FILE", cfg.NATSAuth.AuthAccountSigningKeyFile)
	cfg.NATSAuth.UserJWTTTLMS = envUint64("NEXUS_NATSAUTH_USER_JWT_TTL_MS", cfg.NATSAuth.UserJWTTTLMS)
	cfg.NATSAuth.ChainQueryCacheTTLMS = envUint64("NEXUS_NATSAUTH_CHAIN_QUERY_CACHE_TTL_MS", cfg.NATSAuth.ChainQueryCacheTTLMS)
	cfg.NATSAuth.MaxClockSkewMS = envUint64("NEXUS_NATSAUTH_MAX_CLOCK_SKEW_MS", cfg.NATSAuth.MaxClockSkewMS)
	cfg.NATSAuth.XKeyFile = env("NEXUS_NATSAUTH_XKEY_FILE", cfg.NATSAuth.XKeyFile)
	cfg.Security.Mode = SecurityMode(strings.ToLower(strings.TrimSpace(env("NEXUS_SECURITY_MODE", string(cfg.Security.Mode)))))
	cfg.Chain.GRPCAddr = env("NEXUS_CHAIN_GRPC", cfg.Chain.GRPCAddr)
	cfg.Chain.ChainID = env("NEXUS_CHAIN_ID", cfg.Chain.ChainID)
	cfg.Chain.GasLimit = uint64(envInt("NEXUS_TX_GAS_LIMIT", int(cfg.Chain.GasLimit)))
	cfg.Chain.FeeDenom = env("NEXUS_TX_FEE_DENOM", cfg.Chain.FeeDenom)
	cfg.Chain.FeeAmount = env("NEXUS_TX_FEE_AMOUNT", cfg.Chain.FeeAmount)
	cfg.Chain.DeadlineSweep.Enabled = envBool("NEXUS_DEADLINE_SWEEP_ENABLED", cfg.Chain.DeadlineSweep.Enabled)
	cfg.Chain.DeadlineSweep.GraceBlocks = envUint64("NEXUS_DEADLINE_SWEEP_GRACE_BLOCKS", cfg.Chain.DeadlineSweep.GraceBlocks)
	cfg.Hub.Enabled = envBool("NEXUS_HUB_ENABLED", cfg.Hub.Enabled)
	cfg.Hub.GRPCAddr = env("NEXUS_HUB_GRPC", cfg.Hub.GRPCAddr)
	cfg.Hub.ChainID = env("NEXUS_HUB_CHAIN_ID", cfg.Hub.ChainID)
	cfg.Hub.GasLimit = uint64(envInt("NEXUS_HUB_TX_GAS_LIMIT", int(cfg.Hub.GasLimit)))
	cfg.Hub.FeeDenom = env("NEXUS_HUB_TX_FEE_DENOM", cfg.Hub.FeeDenom)
	cfg.Hub.FeeAmount = env("NEXUS_HUB_TX_FEE_AMOUNT", cfg.Hub.FeeAmount)
	cfg.Identity.BuilderAddress = env("NEXUS_BUILDER_ADDRESS", cfg.Identity.BuilderAddress)
	cfg.Identity.Bech32Prefix = env("NEXUS_BECH32_PREFIX", cfg.Identity.Bech32Prefix)
	cfg.Identity.KeystoreFile = env("NEXUS_KEYSTORE_FILE", cfg.Identity.KeystoreFile)
	cfg.Identity.KeystorePassword = env("NEXUS_KEYSTORE_PASSWORD", cfg.Identity.KeystorePassword)
	cfg.Identity.KeystorePasswordFile = env("NEXUS_KEYSTORE_PASSWORD_FILE", cfg.Identity.KeystorePasswordFile)
	cfg.Identity.PrivateKey = env("NEXUS_PRIVATE_KEY", cfg.Identity.PrivateKey)
	cfg.Identity.PrivateKeyHex = env("NEXUS_PRIVATE_KEY_HEX", cfg.Identity.PrivateKeyHex)
	cfg.Identity.PrivateKeyFile = env("NEXUS_PRIVATE_KEY_FILE", cfg.Identity.PrivateKeyFile)
	cfg.Identity.ServiceKeystoreFile = env("NEXUS_SERVICE_KEYSTORE_FILE", cfg.Identity.ServiceKeystoreFile)
	cfg.Identity.ServiceKeystorePassword = env("NEXUS_SERVICE_KEYSTORE_PASSWORD", cfg.Identity.ServiceKeystorePassword)
	cfg.Identity.ServiceKeystorePasswordFile = env("NEXUS_SERVICE_KEYSTORE_PASSWORD_FILE", cfg.Identity.ServiceKeystorePasswordFile)
	cfg.Identity.PublicEndpoint = env("NEXUS_PUBLIC_ENDPOINT", cfg.Identity.PublicEndpoint)
	cfg.Identity.Moniker = env("NEXUS_BUILDER_MONIKER", cfg.Identity.Moniker)
	cfg.Identity.P2PHint = env("NEXUS_BUILDER_P2P_HINT", cfg.Identity.P2PHint)
	cfg.Identity.DescriptorValidityBlocks = envUint64("NEXUS_DESCRIPTOR_VALIDITY_BLOCKS", cfg.Identity.DescriptorValidityBlocks)
	cfg.Identity.DescriptorRenewBeforeBlocks = envUint64("NEXUS_DESCRIPTOR_RENEW_BEFORE_BLOCKS", cfg.Identity.DescriptorRenewBeforeBlocks)
}

func nonEmptyEnv(key string) (string, bool) {
	value, ok := os.LookupEnv(key)
	return value, ok && value != ""
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envUint64(key string, def uint64) uint64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envUint32(key string, def uint32) uint32 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			return uint32(n)
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func splitNonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
