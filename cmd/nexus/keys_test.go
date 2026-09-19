package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/signer"
)

// Fixed test-only key; never use it for a real account.
const cliTestKeyHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

func TestCreateKeystoreFromPrivateKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "private-key.txt")
	output := filepath.Join(dir, "custom.keystore")
	if err := os.WriteFile(keyFile, []byte("0x"+cliTestKeyHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newKeysCmdWithDeps(keysCommandDeps{
		readSecret:   secretSequence(t, "password", "password"),
		writeFile:    writeNewKeystoreFile,
		bech32Prefix: func(*cobra.Command) string { return "trueopen" },
	})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"create-keystore", "--private-key-file", keyFile, "--output", output})
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
	loaded, err := signer.LoadKeystoreFile(output, []byte("password"), "trueopen")
	if err != nil {
		t.Fatal(err)
	}
	wantOutput := fmt.Sprintf("keystore: %s\naddress: %s\n", output, loaded.Address())
	if stdout.String() != wantOutput {
		t.Fatalf("stdout = %q, want %q", stdout.String(), wantOutput)
	}
	assertNoSecret(t, stdout.String()+stderr.String(), cliTestKeyHex, "password")
}

func TestCreateKeystoreInteractiveUsesDefaultOutput(t *testing.T) {
	t.Chdir(t.TempDir())
	cmd := newKeysCmdWithDeps(keysCommandDeps{
		readSecret:   secretSequence(t, cliTestKeyHex, "password", "password"),
		writeFile:    writeNewKeystoreFile,
		bech32Prefix: func(*cobra.Command) string { return "trueopen" },
	})
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"create-keystore"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("builder.keystore"); err != nil {
		t.Fatalf("default output: %v", err)
	}
}

func TestCreateKeystoreUsesPreparedConfigPrefix(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "builder.keystore")
	cmd := newKeysCmdWithDeps(keysCommandDeps{
		readSecret: secretSequence(t, cliTestKeyHex, "password", "password"),
		writeFile:  writeNewKeystoreFile,
		bech32Prefix: func(cmd *cobra.Command) string {
			return cfgFrom(cmd).Identity.Bech32Prefix
		},
	})
	cfg := config.Config{Identity: config.IdentityConfig{Bech32Prefix: "custom"}}
	cmd.SetContext(context.WithValue(context.Background(), cfgKey, cfg))
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"create-keystore", "--output", output})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	loaded, err := signer.LoadKeystoreFile(output, []byte("password"), "custom")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "address: "+loaded.Address()) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestCreateKeystoreRejectsInvalidPasswords(t *testing.T) {
	tests := map[string][]string{
		"empty":    {cliTestKeyHex, ""},
		"mismatch": {cliTestKeyHex, "first", "second"},
	}
	for name, secrets := range tests {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "builder.keystore")
			cmd := newKeysCmdWithDeps(keysCommandDeps{
				readSecret:   secretSequence(t, secrets...),
				writeFile:    writeNewKeystoreFile,
				bech32Prefix: func(*cobra.Command) string { return "trueopen" },
			})
			cmd.SetArgs([]string{"create-keystore", "--output", output})
			if err := cmd.Execute(); err == nil {
				t.Fatal("expected password error")
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("keystore created after password error: %v", err)
			}
		})
	}
}

func TestCreateKeystoreRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "builder.keystore")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newKeysCmdWithDeps(keysCommandDeps{
		readSecret:   secretSequence(t, cliTestKeyHex, "password", "password"),
		writeFile:    writeNewKeystoreFile,
		bech32Prefix: func(*cobra.Command) string { return "trueopen" },
	})
	cmd.SetArgs([]string{"create-keystore", "--output", path})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected overwrite error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("existing file changed to %q", got)
	}
}

func TestCreateKeystoreDoesNotLeakSecretsOnError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	cmd := newKeysCmdWithDeps(keysCommandDeps{
		readSecret: secretSequence(t, cliTestKeyHex, "password", "password"),
		writeFile: func(string, []byte) error {
			return errors.New("forced write failure")
		},
		bech32Prefix: func(*cobra.Command) string { return "trueopen" },
	})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"create-keystore"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected write error")
	}
	assertNoSecret(t, stdout.String()+stderr.String()+err.Error(), cliTestKeyHex, "password")
}

func TestWriteNewKeystoreFileRemovesPartialOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "builder.keystore")
	open := func(name string, flag int, perm os.FileMode) (syncWriteCloser, error) {
		f, err := os.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		return &failingWriteFile{File: f}, nil
	}
	if err := writeNewKeystoreFileWith(path, []byte("armor"), open, os.Remove); err == nil {
		t.Fatal("expected write error")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial output still exists: %v", err)
	}
}

func TestWriteNewKeystoreFileRemovesOutputAfterSyncOrCloseFailure(t *testing.T) {
	tests := map[string]func(*os.File) syncWriteCloser{
		"sync": func(f *os.File) syncWriteCloser {
			return &failingSyncFile{File: f}
		},
		"close": func(f *os.File) syncWriteCloser {
			return &failingCloseFile{File: f}
		},
	}
	for name, wrap := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "builder.keystore")
			open := func(name string, flag int, perm os.FileMode) (syncWriteCloser, error) {
				f, err := os.OpenFile(name, flag, perm)
				if err != nil {
					return nil, err
				}
				return wrap(f), nil
			}
			if err := writeNewKeystoreFileWith(path, []byte("armor"), open, os.Remove); err == nil {
				t.Fatal("expected file operation error")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial output still exists: %v", err)
			}
		})
	}
}

func TestWriteNewKeystoreFileReportsCleanupFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "builder.keystore")
	open := func(name string, flag int, perm os.FileMode) (syncWriteCloser, error) {
		f, err := os.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		return &failingWriteFile{File: f}, nil
	}
	err := writeNewKeystoreFileWith(path, []byte("armor"), open, func(string) error {
		return errors.New("remove failed")
	})
	if err == nil || !strings.Contains(err.Error(), "remove failed") {
		t.Fatalf("error = %v, want cleanup failure", err)
	}
}

func TestReadSecretFromTerminalRejectsNonTerminal(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("secret"))
	if _, err := readSecretFromTerminal(cmd, "Secret: "); err == nil {
		t.Fatal("expected non-terminal error")
	}
}

func TestRootRegistersKeysCommand(t *testing.T) {
	root := newRootCmd()
	cmd, _, err := root.Find([]string{"keys", "create-keystore"})
	if err != nil {
		t.Fatalf("find command: %v", err)
	}
	if cmd.Name() != "create-keystore" {
		t.Fatalf("command = %q", cmd.Name())
	}
}

type failingWriteFile struct{ *os.File }

func (f *failingWriteFile) Write(p []byte) (int, error) {
	n, _ := f.File.Write(p[:1])
	return n, errors.New("forced write failure")
}

type failingSyncFile struct{ *os.File }

func (f *failingSyncFile) Sync() error { return errors.New("forced sync failure") }

type failingCloseFile struct{ *os.File }

func (f *failingCloseFile) Close() error {
	_ = f.File.Close()
	return errors.New("forced close failure")
}

func secretSequence(t *testing.T, values ...string) secretReader {
	t.Helper()
	index := 0
	return func(_ *cobra.Command, _ string) ([]byte, error) {
		if index >= len(values) {
			t.Fatal("unexpected secret prompt")
		}
		value := []byte(values[index])
		index++
		return value, nil
	}
}

func assertNoSecret(t *testing.T, output string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(output, secret) {
			t.Fatalf("output leaked secret %q", secret)
		}
	}
}
