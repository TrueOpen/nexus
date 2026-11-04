package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/TrueOpen/nexus/internal/signer"
)

var (
	// ErrNoVRFKey means the chain has no active Builder VRF key for the epoch: the Builder must not
	// dispatch orders of that epoch.
	ErrNoVRFKey = errors.New("no active builder VRF key for the epoch")
	// ErrVRFKeyMismatch means none of the local VRF keys is the key the chain registered for the
	// epoch.
	ErrVRFKeyMismatch = errors.New("local VRF keys do not include the chain's registered builder VRF key")
)

// PendingVRFKeyError is ErrNoVRFKey while the chain holds only a pending Builder VRF key: PubKey
// becomes active from FromEpoch, unless its activation is postponed.
type PendingVRFKeyError struct {
	FromEpoch uint64
	PubKey    []byte
}

func (e *PendingVRFKeyError) Error() string {
	return fmt.Sprintf("only a pending key (from epoch %d): %v", e.FromEpoch, ErrNoVRFKey)
}

func (e *PendingVRFKeyError) Unwrap() error { return ErrNoVRFKey }

// VRFKeyRegistry reads this Builder's registered VRF public keys from the chain.
type VRFKeyRegistry interface {
	// BuilderVRFKey returns the 32-byte VRF public key registered for this Builder and active in
	// epoch. When the chain has no active key for that epoch the error wraps ErrNoVRFKey, as a
	// *PendingVRFKeyError when it holds only a pending key; any other error means the chain could
	// not be read.
	BuilderVRFKey(ctx context.Context, epoch uint64) ([]byte, error)
}

// VRFKeys holds the local Builder VRF private keys. A registration takes effect at the next epoch
// boundary and proofs of an epoch must use the key active in that epoch, so earlier keys stay
// loaded until no unexpired order of their epochs remains; the chain's registered key for an
// epoch selects which local key proves it.
type VRFKeys struct {
	keys     []ed25519.PrivateKey
	registry VRFKeyRegistry
}

// NewVRFKeys holds keys, selected per epoch by registry.
func NewVRFKeys(keys []ed25519.PrivateKey, registry VRFKeyRegistry) (*VRFKeys, error) {
	if len(keys) == 0 || registry == nil {
		return nil, fmt.Errorf("VRF keys need at least one key and the chain key registry")
	}
	seen := map[string]bool{}
	out := make([]ed25519.PrivateKey, len(keys))
	for i, key := range keys {
		if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
			return nil, fmt.Errorf("VRF key %d is not a valid Ed25519 private key", i)
		}
		pub := string(key.Public().(ed25519.PublicKey))
		if seen[pub] {
			return nil, fmt.Errorf("VRF key %d is listed twice", i)
		}
		seen[pub] = true
		out[i] = append(ed25519.PrivateKey(nil), key...)
	}
	return &VRFKeys{keys: out, registry: registry}, nil
}

// KeyFor returns the local key equal to the key the chain registered for epoch.
func (k *VRFKeys) KeyFor(ctx context.Context, epoch uint64) (ed25519.PrivateKey, error) {
	registered, err := k.registry.BuilderVRFKey(ctx, epoch)
	if err != nil {
		return nil, fmt.Errorf("read builder VRF key of epoch %d: %w", epoch, err)
	}
	if len(registered) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("builder VRF key of epoch %d is %d bytes, want %d", epoch, len(registered), ed25519.PublicKeySize)
	}
	for _, key := range k.keys {
		if bytes.Equal(key.Public().(ed25519.PublicKey), registered) {
			return key, nil
		}
	}
	return nil, fmt.Errorf("epoch %d: %w", epoch, ErrVRFKeyMismatch)
}

// PublicKeyFor returns the public key of the local key the chain registered for epoch.
func (k *VRFKeys) PublicKeyFor(ctx context.Context, epoch uint64) (ed25519.PublicKey, error) {
	key, err := k.KeyFor(ctx, epoch)
	if err != nil {
		return nil, err
	}
	return key.Public().(ed25519.PublicKey), nil
}

// Ready reports whether orders of epoch can be dispatched: the chain has an active Builder VRF key
// for it and a local key matches it. Workload readiness checks the current epoch. While the chain
// holds only a pending key the error is that *PendingVRFKeyError when a local key matches the
// pending key, and ErrVRFKeyMismatch when none does.
func (k *VRFKeys) Ready(ctx context.Context, epoch uint64) error {
	_, err := k.KeyFor(ctx, epoch)
	var pending *PendingVRFKeyError
	if errors.As(err, &pending) && !k.holds(pending.PubKey) {
		return fmt.Errorf("epoch %d: pending key %x: %w", epoch, pending.PubKey, ErrVRFKeyMismatch)
	}
	return err
}

func (k *VRFKeys) holds(pub []byte) bool {
	for _, key := range k.keys {
		if bytes.Equal(key.Public().(ed25519.PublicKey), pub) {
			return true
		}
	}
	return false
}

// LoadVRFKeys reads VRF key files (Ed25519 in the Cosmos keystore armor) sharing the passphrase in
// passwordFile. Neither the key files nor the password file may be accessible to group or others.
func LoadVRFKeys(files []string, passwordFile string) ([]ed25519.PrivateKey, error) {
	if len(files) == 0 || strings.TrimSpace(passwordFile) == "" {
		return nil, fmt.Errorf("VRF keys need at least one key file and a password file")
	}
	passphrase, err := ReadVRFKeyPassword(passwordFile)
	if err != nil {
		return nil, err
	}
	keys := make([]ed25519.PrivateKey, 0, len(files))
	for _, file := range files {
		armored, err := readPrivateFile(file)
		if err != nil {
			return nil, fmt.Errorf("VRF key file: %w", err)
		}
		key, err := signer.LoadEd25519KeystoreArmor(armored, passphrase)
		if err != nil {
			return nil, fmt.Errorf("VRF key file %s: %w", file, err)
		}
		for _, prev := range keys {
			if bytes.Equal(prev, key) {
				return nil, fmt.Errorf("VRF key file %s repeats an earlier key", file)
			}
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// ReadVRFKeyPassword reads the VRF key passphrase from passwordFile, which group and others may not
// access; trailing CR/LF are trimmed and the passphrase must not be empty.
func ReadVRFKeyPassword(passwordFile string) ([]byte, error) {
	if strings.TrimSpace(passwordFile) == "" {
		return nil, fmt.Errorf("VRF key password file is required")
	}
	raw, err := readPrivateFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("VRF key password file: %w", err)
	}
	passphrase := []byte(strings.TrimRight(string(raw), "\r\n"))
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("VRF key password file %s is empty", passwordFile)
	}
	return passphrase, nil
}

// readPrivateFile reads a regular file that group and others cannot access (mode 0600 or 0400).
func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %04o; it must not be accessible to group or others (chmod 600)", path, perm)
	}
	return os.ReadFile(path)
}
