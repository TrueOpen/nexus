package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutputDeliveryDefaults(t *testing.T) {
	cfg := defaults().OutputDelivery
	if cfg.RequirePlaintextOutput || cfg.MaxBytes != 1<<20 ||
		cfg.PlaintextTTL != 4*time.Hour || cfg.TombstoneTTL != 24*time.Hour ||
		cfg.SweepInterval != time.Minute {
		t.Fatalf("output delivery defaults = %+v", cfg)
	}
}

func TestPayloadStorageDefaultsAndEnvironment(t *testing.T) {
	if got := defaults().PayloadStorage.MaxBytes; got != 16<<20 {
		t.Fatalf("payload storage default max bytes = %d, want %d", got, 16<<20)
	}
	t.Setenv("NEXUS_PAYLOAD_MAX_BYTES", "2097152")
	if got := Load().PayloadStorage.MaxBytes; got != 2<<20 {
		t.Fatalf("payload storage env max bytes = %d, want %d", got, 2<<20)
	}
}

func TestTaskDataDefaults(t *testing.T) {
	got := defaults().TaskData
	if got.InlineMaxBytes != 1<<20 || got.ChunkSizeBytes != 256<<10 || got.MaxRangeBytes != 8<<20 ||
		got.MaxBlobBytes != 1<<30 || got.SpoolReservationBytes != 4<<30 || got.DiskAcceptWatermarkPercent != 85 ||
		got.RequestTTLBlocks != 20 || got.RetentionLeaseBlocks != 1000 || got.SweepInterval != time.Minute {
		t.Fatalf("task data defaults = %+v", got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestTaskDataEnvironment(t *testing.T) {
	t.Setenv("NEXUS_TASK_DATA_INLINE_MAX_BYTES", "1024")
	t.Setenv("NEXUS_TASK_DATA_CHUNK_SIZE_BYTES", "2048")
	t.Setenv("NEXUS_TASK_DATA_MAX_RANGE_BYTES", "4096")
	t.Setenv("NEXUS_TASK_DATA_MAX_BLOB_BYTES", "8192")
	t.Setenv("NEXUS_TASK_DATA_SPOOL_RESERVATION_BYTES", "16384")
	t.Setenv("NEXUS_TASK_DATA_DISK_ACCEPT_WATERMARK_PERCENT", "72")
	t.Setenv("NEXUS_TASK_DATA_REQUEST_TTL_BLOCKS", "12")
	t.Setenv("NEXUS_TASK_DATA_RETENTION_LEASE_BLOCKS", "34")
	t.Setenv("NEXUS_TASK_DATA_SWEEP_INTERVAL", "30s")
	got := Load().TaskData
	if got.InlineMaxBytes != 1024 || got.ChunkSizeBytes != 2048 || got.MaxRangeBytes != 4096 ||
		got.MaxBlobBytes != 8192 || got.SpoolReservationBytes != 16384 || got.DiskAcceptWatermarkPercent != 72 ||
		got.RequestTTLBlocks != 12 || got.RetentionLeaseBlocks != 34 || got.SweepInterval != 30*time.Second {
		t.Fatalf("task data environment = %+v", got)
	}
}

func TestTaskDataWatermarkEnvironmentRejectsUint32Overflow(t *testing.T) {
	t.Setenv("NEXUS_TASK_DATA_DISK_ACCEPT_WATERMARK_PERCENT", "4294967380")
	if got := Load().TaskData.DiskAcceptWatermarkPercent; got != 85 {
		t.Fatalf("overflow watermark = %d, want default 85", got)
	}
}

func TestLoadFileTaskData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	body := []byte("task_data:\n  inline_max_bytes: 1024\n  chunk_size_bytes: 2048\n  max_range_bytes: 4096\n  max_blob_bytes: 8192\n  spool_reservation_bytes: 16384\n  disk_accept_watermark_percent: 70\n  request_ttl_blocks: 12\n  retention_lease_blocks: 34\n  sweep_interval: 45s\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TaskData.MaxBlobBytes != 8192 || cfg.TaskData.DiskAcceptWatermarkPercent != 70 ||
		cfg.TaskData.RequestTTLBlocks != 12 || cfg.TaskData.RetentionLeaseBlocks != 34 || cfg.TaskData.SweepInterval != 45*time.Second {
		t.Fatalf("task data yaml = %+v", cfg.TaskData)
	}
}

func TestExampleConfigStrictlyLoadsWithTaskDataDefaults(t *testing.T) {
	cfg, err := LoadFile(filepath.Join("..", "..", "nexus.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.TaskData.Validate(); err != nil {
		t.Fatalf("example task data config: %v", err)
	}
	if cfg.TaskData.RequestTTLBlocks != 20 || cfg.TaskData.RetentionLeaseBlocks != 1000 || cfg.TaskData.SweepInterval != time.Minute {
		t.Fatalf("example task data config = %+v", cfg.TaskData)
	}
	// The example configuration of the public deadline runner (§9.6a): disabled by default, turning it on is an operational decision.
	if cfg.Chain.DeadlineSweep.Enabled || cfg.Chain.DeadlineSweep.GraceBlocks != 10 {
		t.Fatalf("example deadline sweep config = %+v, want disabled with a non-zero grace window", cfg.Chain.DeadlineSweep)
	}
}

func TestTaskDataConfigRejectsInvalidCombinations(t *testing.T) {
	valid := defaults().TaskData
	tests := map[string]TaskDataConfig{
		"zero inline":       func() TaskDataConfig { v := valid; v.InlineMaxBytes = 0; return v }(),
		"chunk above range": func() TaskDataConfig { v := valid; v.ChunkSizeBytes = v.MaxRangeBytes + 1; return v }(),
		"range above blob":  func() TaskDataConfig { v := valid; v.MaxRangeBytes = v.MaxBlobBytes + 1; return v }(),
		"inline above blob": func() TaskDataConfig { v := valid; v.InlineMaxBytes = v.MaxBlobBytes + 1; return v }(),
		"reserve below blob": func() TaskDataConfig {
			v := valid
			v.SpoolReservationBytes = v.MaxBlobBytes - 1
			return v
		}(),
		"zero watermark":         func() TaskDataConfig { v := valid; v.DiskAcceptWatermarkPercent = 0; return v }(),
		"full watermark":         func() TaskDataConfig { v := valid; v.DiskAcceptWatermarkPercent = 100; return v }(),
		"zero request ttl":       func() TaskDataConfig { v := valid; v.RequestTTLBlocks = 0; return v }(),
		"zero authorization ttl": func() TaskDataConfig { v := valid; v.RetentionLeaseBlocks = 0; return v }(),
		"zero sweep interval":    func() TaskDataConfig { v := valid; v.SweepInterval = 0; return v }(),
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate(%+v) succeeded", cfg)
			}
		})
	}
}

func TestLoadFilePayloadStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(path, []byte("payload_storage:\n  max_bytes: 4194304\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PayloadStorage.MaxBytes != 4<<20 {
		t.Fatalf("payload storage yaml = %+v", cfg.PayloadStorage)
	}
}

func TestOutputDeliveryEnvironment(t *testing.T) {
	t.Setenv("NEXUS_OUTPUT_REQUIRE_PLAINTEXT", "true")
	t.Setenv("NEXUS_OUTPUT_MAX_BYTES", "2048")
	t.Setenv("NEXUS_OUTPUT_PLAINTEXT_TTL", "2h")
	t.Setenv("NEXUS_OUTPUT_TOMBSTONE_TTL", "12h")
	t.Setenv("NEXUS_OUTPUT_SWEEP_INTERVAL", "30s")
	cfg := Load().OutputDelivery
	if !cfg.RequirePlaintextOutput || cfg.MaxBytes != 2048 ||
		cfg.PlaintextTTL != 2*time.Hour || cfg.TombstoneTTL != 12*time.Hour ||
		cfg.SweepInterval != 30*time.Second {
		t.Fatalf("output delivery env = %+v", cfg)
	}
}

func TestLoadFileOutputDelivery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(path, []byte(`
output_delivery:
  require_plaintext_output: true
  output_max_bytes: 4096
  plaintext_ttl: 3h
  tombstone_ttl: 18h
  sweep_interval: 45s
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.OutputDelivery
	if !got.RequirePlaintextOutput || got.MaxBytes != 4096 || got.PlaintextTTL != 3*time.Hour ||
		got.TombstoneTTL != 18*time.Hour || got.SweepInterval != 45*time.Second {
		t.Fatalf("output delivery yaml = %+v", got)
	}
}

func TestLoadPrivateKeyIdentityConfig(t *testing.T) {
	t.Setenv("NEXUS_PRIVATE_KEY", "-----BEGIN TENDERMINT PRIVATE KEY-----")
	t.Setenv("NEXUS_PRIVATE_KEY_HEX", "abc123")
	t.Setenv("NEXUS_PRIVATE_KEY_FILE", "/tmp/builder.key")

	cfg := Load()
	if cfg.Identity.PrivateKey != "-----BEGIN TENDERMINT PRIVATE KEY-----" {
		t.Fatalf("PrivateKey = %q", cfg.Identity.PrivateKey)
	}
	if cfg.Identity.PrivateKeyHex != "abc123" {
		t.Fatalf("PrivateKeyHex = %q", cfg.Identity.PrivateKeyHex)
	}
	if cfg.Identity.PrivateKeyFile != "/tmp/builder.key" {
		t.Fatalf("PrivateKeyFile = %q", cfg.Identity.PrivateKeyFile)
	}
}

func TestLoadServiceIdentityConfig(t *testing.T) {
	t.Setenv("NEXUS_SERVICE_KEYSTORE_FILE", "/tmp/service.key")
	t.Setenv("NEXUS_SERVICE_KEYSTORE_PASSWORD", "secret")
	t.Setenv("NEXUS_SERVICE_KEYSTORE_PASSWORD_FILE", "/tmp/service.password")
	t.Setenv("NEXUS_DESCRIPTOR_VALIDITY_BLOCKS", "200000")
	t.Setenv("NEXUS_DESCRIPTOR_RENEW_BEFORE_BLOCKS", "20000")

	cfg := Load()
	if cfg.Identity.ServiceKeystoreFile != "/tmp/service.key" ||
		cfg.Identity.ServiceKeystorePassword != "secret" ||
		cfg.Identity.ServiceKeystorePasswordFile != "/tmp/service.password" ||
		cfg.Identity.DescriptorValidityBlocks != 200000 ||
		cfg.Identity.DescriptorRenewBeforeBlocks != 20000 {
		t.Fatalf("identity = %+v", cfg.Identity)
	}
}

func TestServiceIdentityDefaults(t *testing.T) {
	cfg := defaults()
	if cfg.Identity.DescriptorValidityBlocks != 100000 || cfg.Identity.DescriptorRenewBeforeBlocks != 10000 {
		t.Fatalf("descriptor defaults = %d/%d", cfg.Identity.DescriptorValidityBlocks, cfg.Identity.DescriptorRenewBeforeBlocks)
	}
}

func TestLoadFileMergesDefaultsYAMLAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nexus.yaml")
	err := os.WriteFile(path, []byte(`
data_dir: ./state
nats:
  servers: [nats://yaml:4222]
chain:
  grpc_addr: yaml-node:9090
  gas_limit: 300000
identity:
  private_key_file: ./builder.key
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_CHAIN_GRPC", "env-node:9090")
	t.Setenv("NEXUS_DATA_DIR", "")
	t.Setenv("NEXUS_NATS_SERVERS", "")
	t.Setenv("NEXUS_PRIVATE_KEY_FILE", "")

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chain.GRPCAddr != "env-node:9090" {
		t.Fatalf("grpc = %q", cfg.Chain.GRPCAddr)
	}
	if cfg.Chain.GasLimit != 300000 || cfg.Log.Level != "info" {
		t.Fatalf("config = %+v", cfg)
	}
	if len(cfg.NATS.Servers) != 1 || cfg.NATS.Servers[0] != "nats://yaml:4222" {
		t.Fatalf("nats servers = %#v", cfg.NATS.Servers)
	}
	if cfg.DataDir != filepath.Join(dir, "state") {
		t.Fatalf("data dir = %q", cfg.DataDir)
	}
	if cfg.Identity.PrivateKeyFile != filepath.Join(dir, "builder.key") {
		t.Fatalf("private key file = %q", cfg.Identity.PrivateKeyFile)
	}
}

func TestLoadFileRejectsInvalidYAML(t *testing.T) {
	tests := map[string]struct {
		body    string
		wantErr string
	}{
		"unknown field": {
			body:    "chain:\n  grpc_adrr: localhost:9090\n",
			wantErr: "field grpc_adrr not found",
		},
		"invalid type": {
			body:    "chain:\n  gas_limit: invalid\n",
			wantErr: "cannot unmarshal",
		},
		"multiple documents": {
			body:    "chain:\n  chain_id: one\n---\nchain:\n  chain_id: two\n",
			wantErr: "multiple YAML documents",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nexus.yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFile(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), path) {
				t.Fatalf("error = %v, want path and %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFileAcceptsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_CHAIN_GRPC", "")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chain.GRPCAddr != "localhost:9090" {
		t.Fatalf("grpc = %q", cfg.Chain.GRPCAddr)
	}
}

func TestLoadFileReturnsMissingExplicitFileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %v, want missing path", err)
	}
}

// nats.sentinel_file behaves like ca_file / creds_file: a relative path in the YAML resolves against the directory holding the config file.
func TestLoadFileResolvesNATSSentinelFileRelativeToConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nexus.yaml")
	if err := os.WriteFile(path, []byte("nats:\n  sentinel_file: ./nats-sentinel.jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_NATS_SENTINEL_FILE", "")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NATS.SentinelFile != filepath.Join(dir, "nats-sentinel.jwt") {
		t.Fatalf("sentinel file = %q", cfg.NATS.SentinelFile)
	}
}

func TestLoadFileEnvironmentPathOverrideRemainsProcessRelative(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nexus.yaml")
	if err := os.WriteFile(path, []byte("identity:\n  private_key_file: ./yaml.key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_PRIVATE_KEY_FILE", "./env.key")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.PrivateKeyFile != "./env.key" {
		t.Fatalf("private key file = %q", cfg.Identity.PrivateKeyFile)
	}
}

func TestLoadFileMergesHubYAMLAndEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(path, []byte(`
hub:
  enabled: true
  grpc_addr: yaml-hub:9090
  chain_id: trueopen-hub
  gas_limit: 300000
  fee_denom: utrueopen
  fee_amount: "7"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEXUS_HUB_GRPC", "env-hub:9090")

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Hub.Enabled || cfg.Hub.GRPCAddr != "env-hub:9090" ||
		cfg.Hub.ChainID != "trueopen-hub" || cfg.Hub.GasLimit != 300000 || cfg.Hub.FeeDenom != "utrueopen" || cfg.Hub.FeeAmount != "7" {
		t.Fatalf("hub = %+v", cfg.Hub)
	}
}

func TestBuilderAuthorityRequiresCompleteEnabledHub(t *testing.T) {
	cfg := defaults()
	cfg.Hub.Enabled = true

	if _, err := cfg.BuilderAuthority(); err == nil || !strings.Contains(err.Error(), "enabled hub requires") {
		t.Fatalf("error = %v, want incomplete hub error", err)
	}
}

func TestBuilderAuthorityUsesHubWhenEnabled(t *testing.T) {
	cfg := defaults()
	cfg.Hub = HubConfig{
		Enabled:   true,
		GRPCAddr:  "hub:9090",
		ChainID:   "trueopen-hub",
		GasLimit:  300000,
		FeeDenom:  "utrueopen",
		FeeAmount: "7",
	}

	authority, err := cfg.BuilderAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if authority.Mode != AuthorityHub || authority.Chain.ChainID != "trueopen-hub" || authority.LegacyChainID != cfg.Chain.ChainID {
		t.Fatalf("authority = %+v", authority)
	}
}

func TestBuilderAuthorityUsesCompatibilityChainWhenHubDisabled(t *testing.T) {
	cfg := defaults()

	authority, err := cfg.BuilderAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if authority.Mode != AuthorityCompatibility || authority.Chain.ChainID != cfg.Chain.ChainID || authority.LegacyChainID != cfg.Chain.ChainID {
		t.Fatalf("authority = %+v", authority)
	}
}

// identity.service_endpoints is the new on-chain descriptor input (§9.6b); the YAML is parsed strictly,
// so a wrong field name or shape blocks startup outright. This test locks in that it parses.
func TestIdentityServiceEndpointsParseFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	body := `identity:
  public_endpoint: "https://builder.example:8080"
  service_endpoints:
    - kind: NEXUS_GRPC
      uri: "grpcs://builder.example:9090"
      protocol_version: "v2"
      tls_pubkey_hash: "aabb112233445566778899aabbccddeeff00112233445566778899aabbccddee"
    - kind: HEALTH_HTTPS
      uri: "https://builder.example:8080/healthz"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Identity.ServiceEndpoints
	if len(got) != 2 {
		t.Fatalf("service endpoints = %+v", got)
	}
	if got[0].Kind != "NEXUS_GRPC" || got[0].URI != "grpcs://builder.example:9090" ||
		got[0].ProtocolVersion != "v2" || len(got[0].TLSPubKeyHash) != 64 {
		t.Fatalf("endpoint 0 = %+v", got[0])
	}
	if got[1].Kind != "HEALTH_HTTPS" || got[1].ProtocolVersion != "" {
		t.Fatalf("endpoint 1 = %+v", got[1])
	}
}

// Unknown fields must still block startup: members of service_endpoints are parsed strictly too.
func TestIdentityServiceEndpointsRejectUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	body := `identity:
  service_endpoints:
    - kind: NEXUS_GRPC
      endpoint: "https://builder.example:8080"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil {
		t.Fatal("an unknown service endpoint field must block startup")
	}
}

func TestExampleYAMLMatchesSchema(t *testing.T) {
	t.Setenv("NEXUS_CHAIN_GRPC", "")
	t.Setenv("NEXUS_PRIVATE_KEY_FILE", "")
	path := filepath.Join("..", "..", "nexus.example.yaml")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chain.GRPCAddr == "" || cfg.Identity.PrivateKeyFile == "" {
		t.Fatalf("incomplete example: %+v", cfg)
	}
}
