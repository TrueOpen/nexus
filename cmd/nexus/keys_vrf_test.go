package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/dispatchdraw"
)

func newTestVRFKeysCmd(t *testing.T, secrets ...string) *cobra.Command {
	t.Helper()
	return newKeysCmdWithDeps(keysCommandDeps{
		readSecret:   secretSequence(t, secrets...),
		writeFile:    writeNewKeystoreFile,
		bech32Prefix: func(*cobra.Command) string { return "trueopen" },
	})
}

func writePrivateTestFile(t *testing.T, path, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// The written file is exactly what `nexus start` loads through identity.vrf_key_files, and the
// printed public key is the key it holds.
func TestCreateVRFKeyWithPasswordFileLoadsAsAVRFKey(t *testing.T) {
	dir := t.TempDir()
	pass := writePrivateTestFile(t, filepath.Join(dir, "vrf.pass"), "vrf-secret\n", 0o600)
	output := filepath.Join(dir, "builder-vrf.keystore")
	cmd := newTestVRFKeysCmd(t)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"create-vrf-key", "--output", output, "--password-file", pass})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	keys, err := dispatchdraw.LoadVRFKeys([]string{output}, pass)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(keys[0].Public().(ed25519.PublicKey))
	want := fmt.Sprintf("vrf_key_file: %s\nvrf_pubkey: %s\n", output, pub)
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	assertNoSecret(t, stdout.String()+stderr.String(), "vrf-secret", hex.EncodeToString(keys[0].Seed()))
}

func TestCreateVRFKeyGeneratesAFreshKeyEachTime(t *testing.T) {
	dir := t.TempDir()
	pass := writePrivateTestFile(t, filepath.Join(dir, "vrf.pass"), "vrf-secret", 0o600)
	var pubs []string
	for _, name := range []string{"a.keystore", "b.keystore"} {
		cmd := newTestVRFKeysCmd(t)
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetArgs([]string{"create-vrf-key", "--output", filepath.Join(dir, name), "--password-file", pass})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, stdout.String()[strings.Index(stdout.String(), "vrf_pubkey: "):])
	}
	if pubs[0] == pubs[1] {
		t.Fatal("two runs produced the same VRF key")
	}
}

func TestCreateVRFKeyInteractiveUsesDefaultOutput(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cmd := newTestVRFKeysCmd(t, "vrf-secret", "vrf-secret")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"create-vrf-key"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	pass := writePrivateTestFile(t, filepath.Join(dir, "vrf.pass"), "vrf-secret", 0o600)
	keys, err := dispatchdraw.LoadVRFKeys([]string{"vrf.keystore"}, pass)
	if err != nil {
		t.Fatalf("default output: %v", err)
	}
	if !strings.Contains(stdout.String(), "vrf_pubkey: "+hex.EncodeToString(keys[0].Public().(ed25519.PublicKey))) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCreateVRFKeyRejectsBadPasswords(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		secrets []string
		file    string
	}{
		"interactive empty":    {secrets: []string{""}},
		"interactive mismatch": {secrets: []string{"first", "second"}},
		"empty file":           {file: writePrivateTestFile(t, filepath.Join(dir, "empty.pass"), "\n", 0o600)},
		"group readable file":  {file: writePrivateTestFile(t, filepath.Join(dir, "loose.pass"), "secret", 0o640)},
		"missing file":         {file: filepath.Join(dir, "missing.pass")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "vrf.keystore")
			cmd := newTestVRFKeysCmd(t, tc.secrets...)
			args := []string{"create-vrf-key", "--output", output}
			if tc.file != "" {
				args = append(args, "--password-file", tc.file)
			}
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetArgs(args)
			if err := cmd.Execute(); err == nil {
				t.Fatal("expected password error")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("key file created after password error: %v", err)
			}
		})
	}
}

func TestCreateVRFKeyRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	pass := writePrivateTestFile(t, filepath.Join(dir, "vrf.pass"), "vrf-secret", 0o600)
	output := writePrivateTestFile(t, filepath.Join(dir, "vrf.keystore"), "keep", 0o600)
	cmd := newTestVRFKeysCmd(t)
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"create-vrf-key", "--output", output, "--password-file", pass})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected overwrite error")
	}
	if got, _ := os.ReadFile(output); string(got) != "keep" {
		t.Fatalf("existing file changed to %q", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout after failure = %q", stdout.String())
	}
}

func TestRootRegistersCreateVRFKeyCommand(t *testing.T) {
	cmd, _, err := newRootCmd().Find([]string{"keys", "create-vrf-key"})
	if err != nil || cmd.Name() != "create-vrf-key" {
		t.Fatalf("find command: %v, %v", cmd, err)
	}
}
