// Package identity loads and validates the local Builder account identity.
package identity

import (
	"fmt"
	"os"
	"strings"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

// LoadSigner loads the Builder account identity.
func LoadSigner(cfg config.IdentityConfig) (signer.Signer, error) {
	if strings.TrimSpace(cfg.KeystoreFile) != "" {
		passphrase, err := passphrase(cfg)
		if err != nil {
			return nil, err
		}
		return signer.LoadKeystoreFile(cfg.KeystoreFile, passphrase, cfg.Bech32Prefix)
	}
	if f := strings.TrimSpace(cfg.PrivateKeyFile); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("identity: read private key file: %w", err)
		}
		pass, err := optionalPassphrase(cfg)
		if err != nil {
			return nil, err
		}
		return signer.LoadPrivateKeyMaterial(b, pass, cfg.Bech32Prefix)
	}
	if h := strings.TrimSpace(cfg.PrivateKey); h != "" {
		pass, err := optionalPassphrase(cfg)
		if err != nil {
			return nil, err
		}
		return signer.LoadPrivateKeyMaterial([]byte(h), pass, cfg.Bech32Prefix)
	}
	if h := strings.TrimSpace(cfg.PrivateKeyHex); h != "" {
		return signer.LoadPrivateKeyMaterial([]byte(h), nil, cfg.Bech32Prefix)
	}
	return nil, nil
}

// LoadServiceSigner loads the Builder service-signing key. When no dedicated
// keystore is configured, the account signer is returned explicitly as shared.
func LoadServiceSigner(cfg config.IdentityConfig, account signer.Signer) (signer.Signer, bool, error) {
	if strings.TrimSpace(cfg.ServiceKeystoreFile) == "" {
		return account, true, nil
	}
	passphrase, err := servicePassphrase(cfg)
	if err != nil {
		return nil, false, err
	}
	loaded, err := signer.LoadKeystoreFile(cfg.ServiceKeystoreFile, passphrase, cfg.Bech32Prefix)
	if err != nil {
		return nil, false, fmt.Errorf("identity: load service keystore: %w", err)
	}
	return loaded, false, nil
}

// LoadNextServiceSigner loads the second BUILDER service key (identity.next_service_keystore_file),
// nil when none is configured. It needs a dedicated service keystore next to it: a service key
// shared with the account key cannot be rotated away from it.
func LoadNextServiceSigner(cfg config.IdentityConfig) (signer.Signer, error) {
	file := strings.TrimSpace(cfg.NextServiceKeystoreFile)
	if file == "" {
		return nil, nil
	}
	if strings.TrimSpace(cfg.ServiceKeystoreFile) == "" {
		return nil, fmt.Errorf("identity: next_service_keystore_file needs service_keystore_file")
	}
	passFile := strings.TrimSpace(cfg.NextServiceKeystorePasswordFile)
	if passFile == "" {
		return nil, fmt.Errorf("identity: next_service_keystore_password_file required")
	}
	b, err := os.ReadFile(passFile)
	if err != nil {
		return nil, fmt.Errorf("identity: read next service keystore password file: %w", err)
	}
	passphrase := []byte(strings.TrimRight(string(b), "\r\n"))
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("identity: next service keystore password is empty")
	}
	loaded, err := signer.LoadKeystoreFile(file, passphrase, cfg.Bech32Prefix)
	if err != nil {
		return nil, fmt.Errorf("identity: load next service keystore: %w", err)
	}
	return loaded, nil
}

// ResolveBuilderAddress returns the effective Builder address and rejects
// conflicting config, because rank/proposer logic and tx signing must agree.
func ResolveBuilderAddress(cfg config.IdentityConfig, sg signer.Signer) (string, error) {
	selfAddr := cfg.BuilderAddress
	if sg == nil {
		return selfAddr, nil
	}
	if selfAddr != "" && selfAddr != sg.Address() {
		return "", fmt.Errorf("identity mismatch: NEXUS_BUILDER_ADDRESS=%s but signer derives %s",
			selfAddr, sg.Address())
	}
	return sg.Address(), nil
}

func passphrase(cfg config.IdentityConfig) ([]byte, error) {
	if f := strings.TrimSpace(cfg.KeystorePasswordFile); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("identity: read keystore password file: %w", err)
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	if cfg.KeystorePassword != "" {
		return []byte(cfg.KeystorePassword), nil
	}
	return nil, fmt.Errorf("identity: NEXUS_KEYSTORE_PASSWORD_FILE or NEXUS_KEYSTORE_PASSWORD required")
}

func optionalPassphrase(cfg config.IdentityConfig) ([]byte, error) {
	if strings.TrimSpace(cfg.KeystorePasswordFile) == "" && cfg.KeystorePassword == "" {
		return nil, nil
	}
	return passphrase(cfg)
}

func servicePassphrase(cfg config.IdentityConfig) ([]byte, error) {
	if f := strings.TrimSpace(cfg.ServiceKeystorePasswordFile); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("identity: read service keystore password file: %w", err)
		}
		passphrase := []byte(strings.TrimRight(string(b), "\r\n"))
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("identity: service keystore password is empty")
		}
		return passphrase, nil
	}
	if cfg.ServiceKeystorePassword != "" {
		return []byte(cfg.ServiceKeystorePassword), nil
	}
	return nil, fmt.Errorf("identity: service keystore password or password file required")
}
