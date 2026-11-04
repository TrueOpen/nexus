package dispatchdraw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func TestLoadVRFKeysReadsEveryListedKey(t *testing.T) {
	dir := t.TempDir()
	a, b := testKey(1), testKey(2)
	files := []string{
		writeKeyFile(t, dir, "vrf-2.key", b, "secret", 0o600),
		writeKeyFile(t, dir, "vrf-1.key", a, "secret", 0o400),
	}
	pass := writeFile(t, dir, "vrf.pass", []byte("secret\n"), 0o600)

	keys, err := LoadVRFKeys(files, pass)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !bytes.Equal(keys[0], b) || !bytes.Equal(keys[1], a) {
		t.Fatal("loaded keys differ from the files")
	}
}

func TestLoadVRFKeysRefusesFilesOthersCanRead(t *testing.T) {
	dir := t.TempDir()
	key := writeKeyFile(t, dir, "vrf.key", testKey(1), "secret", 0o600)
	pass := writeFile(t, dir, "vrf.pass", []byte("secret"), 0o600)
	looseKey := writeKeyFile(t, dir, "loose.key", testKey(1), "secret", 0o644)
	loosePass := writeFile(t, dir, "loose.pass", []byte("secret"), 0o640)

	if _, err := LoadVRFKeys([]string{looseKey}, pass); err == nil || !strings.Contains(err.Error(), "0644") {
		t.Fatalf("group/other readable key file: err = %v", err)
	}
	if _, err := LoadVRFKeys([]string{key}, loosePass); err == nil || !strings.Contains(err.Error(), "0640") {
		t.Fatalf("group readable password file: err = %v", err)
	}
}

func TestLoadVRFKeysRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	key := writeKeyFile(t, dir, "vrf.key", testKey(1), "secret", 0o600)
	pass := writeFile(t, dir, "vrf.pass", []byte("secret"), 0o600)
	empty := writeFile(t, dir, "empty.pass", []byte("\n"), 0o600)
	wrong := writeFile(t, dir, "wrong.pass", []byte("other"), 0o600)

	cases := map[string]struct {
		files []string
		pass  string
	}{
		"no key files":      {nil, pass},
		"no password file":  {[]string{key}, ""},
		"empty password":    {[]string{key}, empty},
		"wrong password":    {[]string{key}, wrong},
		"missing key file":  {[]string{dir + "/missing.key"}, pass},
		"duplicate key":     {[]string{key, key}, pass},
		"directory as file": {[]string{dir}, pass},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadVRFKeys(tc.files, tc.pass); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// The key used for an epoch is the local key equal to the key the chain registered for that epoch,
// so orders of an earlier epoch are still proven with the key that was active then.
func TestVRFKeysSelectTheKeyRegisteredForEachEpoch(t *testing.T) {
	old, cur := testKey(1), testKey(2)
	keys, err := NewVRFKeys([]ed25519.PrivateKey{cur, old}, registryFor(map[uint64]ed25519.PrivateKey{4: old, 5: cur}))
	if err != nil {
		t.Fatal(err)
	}
	for epoch, want := range map[uint64]ed25519.PrivateKey{4: old, 5: cur} {
		got, err := keys.KeyFor(context.Background(), epoch)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("epoch %d: key mismatch, err = %v", epoch, err)
		}
	}
}

func TestVRFKeysReadiness(t *testing.T) {
	local := testKey(1)
	ctx := context.Background()

	keys, _ := NewVRFKeys([]ed25519.PrivateKey{local}, registryFor(map[uint64]ed25519.PrivateKey{5: local}))
	if err := keys.Ready(ctx, 5); err != nil {
		t.Fatalf("matching key: %v", err)
	}

	keys, _ = NewVRFKeys([]ed25519.PrivateKey{local}, registryFor(map[uint64]ed25519.PrivateKey{5: testKey(9)}))
	if err := keys.Ready(ctx, 5); !errors.Is(err, ErrVRFKeyMismatch) {
		t.Fatalf("chain key differs from every local key: err = %v", err)
	}
	if err := keys.Ready(ctx, 6); !errors.Is(err, ErrNoVRFKey) {
		t.Fatalf("no key registered for the epoch: err = %v", err)
	}

	chainDown := errors.New("chain unavailable")
	keys, _ = NewVRFKeys([]ed25519.PrivateKey{local}, &fakeRegistry{err: chainDown})
	if err := keys.Ready(ctx, 5); !errors.Is(err, chainDown) || errors.Is(err, ErrVRFKeyMismatch) {
		t.Fatalf("chain read error: err = %v", err)
	}

	keys, _ = NewVRFKeys([]ed25519.PrivateKey{local}, &fakeRegistry{keys: map[uint64][]byte{5: {1, 2, 3}}})
	if err := keys.Ready(ctx, 5); err == nil {
		t.Fatal("malformed chain key must not be ready")
	}
}

func TestNewVRFKeysRejectsBadKeys(t *testing.T) {
	reg := registryFor(nil)
	if _, err := NewVRFKeys(nil, reg); err == nil {
		t.Fatal("no keys must be rejected")
	}
	if _, err := NewVRFKeys([]ed25519.PrivateKey{testKey(1)}, nil); err == nil {
		t.Fatal("missing registry must be rejected")
	}
	if _, err := NewVRFKeys([]ed25519.PrivateKey{make([]byte, 10)}, reg); err == nil {
		t.Fatal("short key must be rejected")
	}
	if _, err := NewVRFKeys([]ed25519.PrivateKey{testKey(1), testKey(1)}, reg); err == nil {
		t.Fatal("duplicate key must be rejected")
	}
}

// The VRF key password file follows the key file rules: private to its owner, trailing CR/LF
// trimmed, and not empty.
func TestReadVRFKeyPassword(t *testing.T) {
	dir := t.TempDir()
	good := writeFile(t, dir, "vrf.pass", []byte("secret\r\n"), 0o600)
	got, err := ReadVRFKeyPassword(good)
	if err != nil || string(got) != "secret" {
		t.Fatalf("password = %q, %v", got, err)
	}
	for name, path := range map[string]string{
		"empty":          writeFile(t, dir, "empty.pass", []byte("\r\n"), 0o600),
		"group readable": writeFile(t, dir, "loose.pass", []byte("secret"), 0o640),
		"missing":        dir + "/missing.pass",
		"directory":      dir,
		"no path":        " ",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadVRFKeyPassword(path); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
