package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultFile = "nexus.yaml"

// LoadFile applies defaults, an optional YAML file, then environment overrides.
func LoadFile(path string) (Config, error) {
	cfg := defaults()
	if strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
		if err := decodeYAML(path, data, &cfg); err != nil {
			return Config{}, err
		}
		if err := resolveYAMLPaths(path, data, &cfg); err != nil {
			return Config{}, err
		}
	}
	applyEnv(&cfg)
	return cfg, nil
}

func decodeYAML(path string, data []byte, cfg *Config) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode config %q: %w", path, err)
	}

	var extra any
	err := decoder.Decode(&extra)
	switch {
	case errors.Is(err, io.EOF):
		return nil
	case err != nil:
		return fmt.Errorf("decode config %q: %w", path, err)
	default:
		return fmt.Errorf("decode config %q: multiple YAML documents are not supported", path)
	}
}

type yamlPathFields struct {
	DataDir *string `yaml:"data_dir"`
	Log     struct {
		File *string `yaml:"file"`
	} `yaml:"log"`
	Ingress struct {
		TLS struct {
			CertFile *string `yaml:"cert_file"`
			KeyFile  *string `yaml:"key_file"`
		} `yaml:"tls"`
	} `yaml:"ingress"`
	Identity struct {
		KeystoreFile                *string `yaml:"keystore_file"`
		KeystorePasswordFile        *string `yaml:"keystore_password_file"`
		PrivateKeyFile              *string `yaml:"private_key_file"`
		ServiceKeystoreFile         *string `yaml:"service_keystore_file"`
		ServiceKeystorePasswordFile *string `yaml:"service_keystore_password_file"`
	} `yaml:"identity"`
	NATS struct {
		CAFile       *string `yaml:"ca_file"`
		CredsFile    *string `yaml:"creds_file"`
		SentinelFile *string `yaml:"sentinel_file"`
	} `yaml:"nats"`
	NATSAuth struct {
		NATS struct {
			CAFile    *string `yaml:"ca_file"`
			CredsFile *string `yaml:"creds_file"`
		} `yaml:"nats"`
		CortexAccountSigningKeyFile *string `yaml:"cortex_account_signing_key_file"`
		AuthAccountSigningKeyFile   *string `yaml:"auth_account_signing_key_file"`
		XKeyFile                    *string `yaml:"xkey_file"`
	} `yaml:"natsauth"`
}

func resolveYAMLPaths(path string, data []byte, cfg *Config) error {
	var fields yamlPathFields
	if err := yaml.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode config paths %q: %w", path, err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path %q: %w", path, err)
	}
	baseDir := filepath.Dir(absPath)
	if fields.DataDir != nil {
		cfg.DataDir = resolveRelativePath(baseDir, cfg.DataDir)
	}
	if fields.Log.File != nil {
		cfg.Log.File = resolveRelativePath(baseDir, cfg.Log.File)
	}
	if fields.Ingress.TLS.CertFile != nil {
		cfg.Ingress.TLS.CertFile = resolveRelativePath(baseDir, cfg.Ingress.TLS.CertFile)
	}
	if fields.Ingress.TLS.KeyFile != nil {
		cfg.Ingress.TLS.KeyFile = resolveRelativePath(baseDir, cfg.Ingress.TLS.KeyFile)
	}
	if fields.Identity.KeystoreFile != nil {
		cfg.Identity.KeystoreFile = resolveRelativePath(baseDir, cfg.Identity.KeystoreFile)
	}
	if fields.Identity.KeystorePasswordFile != nil {
		cfg.Identity.KeystorePasswordFile = resolveRelativePath(baseDir, cfg.Identity.KeystorePasswordFile)
	}
	if fields.Identity.PrivateKeyFile != nil {
		cfg.Identity.PrivateKeyFile = resolveRelativePath(baseDir, cfg.Identity.PrivateKeyFile)
	}
	if fields.NATS.CAFile != nil {
		cfg.NATS.CAFile = resolveRelativePath(baseDir, cfg.NATS.CAFile)
	}
	if fields.NATS.CredsFile != nil {
		cfg.NATS.CredsFile = resolveRelativePath(baseDir, cfg.NATS.CredsFile)
	}
	if fields.NATS.SentinelFile != nil {
		cfg.NATS.SentinelFile = resolveRelativePath(baseDir, cfg.NATS.SentinelFile)
	}
	if fields.Identity.ServiceKeystoreFile != nil {
		cfg.Identity.ServiceKeystoreFile = resolveRelativePath(baseDir, cfg.Identity.ServiceKeystoreFile)
	}
	if fields.Identity.ServiceKeystorePasswordFile != nil {
		cfg.Identity.ServiceKeystorePasswordFile = resolveRelativePath(baseDir, cfg.Identity.ServiceKeystorePasswordFile)
	}
	if fields.NATSAuth.NATS.CAFile != nil {
		cfg.NATSAuth.NATS.CAFile = resolveRelativePath(baseDir, cfg.NATSAuth.NATS.CAFile)
	}
	if fields.NATSAuth.NATS.CredsFile != nil {
		cfg.NATSAuth.NATS.CredsFile = resolveRelativePath(baseDir, cfg.NATSAuth.NATS.CredsFile)
	}
	if fields.NATSAuth.CortexAccountSigningKeyFile != nil {
		cfg.NATSAuth.CortexAccountSigningKeyFile = resolveRelativePath(baseDir, cfg.NATSAuth.CortexAccountSigningKeyFile)
	}
	if fields.NATSAuth.AuthAccountSigningKeyFile != nil {
		cfg.NATSAuth.AuthAccountSigningKeyFile = resolveRelativePath(baseDir, cfg.NATSAuth.AuthAccountSigningKeyFile)
	}
	if fields.NATSAuth.XKeyFile != nil {
		cfg.NATSAuth.XKeyFile = resolveRelativePath(baseDir, cfg.NATSAuth.XKeyFile)
	}
	return nil
}

func resolveRelativePath(baseDir, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Clean(filepath.Join(baseDir, value))
}
