package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/signer"
)

const vrfCmdHubChainID = "trueopen-hub-localnet"

// fakeVRFKeyHub is the Hub chain as `builder register-vrf-key` uses it: the VRF key row, the
// operator account, broadcast, and a block result that applies the registration like the chain.
// Everything else goes through the embedded nil Client and would panic.
type fakeVRFKeyHub struct {
	chaincli.Client
	row        *chaincli.VrfKey
	broadcasts [][]byte
	// code is the block result code of every broadcast transaction.
	code   uint32
	rawLog string
}

func (h *fakeVRFKeyHub) QueryVrfKey(_ context.Context, participantType, _ string) (chaincli.VrfKey, error) {
	if participantType != "BUILDER" {
		return chaincli.VrfKey{}, fmt.Errorf("participant type %q", participantType)
	}
	if h.row == nil {
		return chaincli.VrfKey{}, chaincli.ErrNotFound
	}
	return *h.row, nil
}

func (h *fakeVRFKeyHub) AccountInfo(context.Context, string) (chaincli.AccountInfo, error) {
	return chaincli.AccountInfo{AccountNumber: 3, Sequence: 9}, nil
}

func (h *fakeVRFKeyHub) BroadcastTx(_ context.Context, tx []byte) (chaincli.TxResult, error) {
	h.broadcasts = append(h.broadcasts, tx)
	sum := sha256.Sum256(tx)
	return chaincli.TxResult{TxHash: sum[:]}, nil
}

func (h *fakeVRFKeyHub) QueryTx(_ context.Context, txHash []byte) (chaincli.TxResult, error) {
	tx := h.broadcasts[len(h.broadcasts)-1]
	if sum := sha256.Sum256(tx); !bytes.Equal(sum[:], txHash) {
		return chaincli.TxResult{}, chaincli.ErrNotFound
	}
	result := chaincli.TxResult{TxHash: txHash, Height: 40, Code: h.code, Codespace: "hub", RawLog: h.rawLog}
	if h.code == 0 {
		msg, err := chaincli.CheckRegisterVrfKeyTx(tx, cliTestBuilderAddress())
		if err != nil {
			return chaincli.TxResult{}, err
		}
		next := chaincli.VrfKey{PendingPubKey: msg.GetVrfPubkey(), PendingFromEpoch: 7, AuthorizationNonce: msg.GetVrfAuthorizationNonce()}
		if h.row != nil {
			next.ActivePubKey, next.ActiveFromEpoch = h.row.ActivePubKey, h.row.ActiveFromEpoch
		}
		h.row = &next
	}
	return result, nil
}

func cliTestBuilderAddress() string {
	sg, err := signer.NewFromHex(cliTestKeyHex, "trueopen")
	if err != nil {
		panic(err)
	}
	return sg.Address()
}

// writeVRFKeyFiles writes one VRF key file per seed and the shared password file, all mode 0600.
func writeVRFKeyFiles(t *testing.T, dir string, seeds ...byte) ([]string, []ed25519.PrivateKey, string) {
	t.Helper()
	pass := writePrivateTestFile(t, filepath.Join(dir, "vrf.pass"), "vrf-secret\n", 0o600)
	var files []string
	var keys []ed25519.PrivateKey
	for _, seed := range seeds {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		armored, err := signer.EncryptEd25519KeystoreArmor(key, []byte("vrf-secret"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, writePrivateTestFile(t, filepath.Join(dir, fmt.Sprintf("vrf-%d.keystore", seed)), string(armored), 0o600))
		keys = append(keys, key)
	}
	return files, keys, pass
}

// executeRegisterVRFKey runs `builder register-vrf-key` against hub with the environment's
// configuration, the way the root command's prepare phase would hand it over.
func executeRegisterVRFKey(t *testing.T, hub *fakeVRFKeyHub, args ...string) (string, error) {
	t.Helper()
	cfg, _, err := loadCommandConfig("", false, configOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	cmd := newBuilderCmdWithDeps(builderCommandDeps{
		newChain: func(_ *slog.Logger, chainCfg config.ChainConfig) chaincli.Client {
			if chainCfg.ChainID != vrfCmdHubChainID {
				t.Errorf("chain client for %q, want the Hub", chainCfg.ChainID)
			}
			return hub
		},
	})
	ctx := context.WithValue(context.Background(), cfgKey, cfg)
	ctx = context.WithValue(ctx, logKey, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cmd.SetContext(ctx)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"register-vrf-key"}, args...))
	err = cmd.Execute()
	return out.String(), err
}

func configureRegisterVRFKey(t *testing.T, files []string, pass string) {
	t.Helper()
	t.Chdir(t.TempDir())
	configureBuilderCommand(t, t.TempDir(), "127.0.0.1:1", "127.0.0.1:2")
	t.Setenv("NEXUS_VRF_KEY_FILES", strings.Join(files, ","))
	t.Setenv("NEXUS_VRF_KEY_PASSWORD_FILE", pass)
}

// With no VRF key on chain, the last configured key file (the newest key) is registered with
// nonce 1 and a possession proof, signed by the Builder operator account; the command reports the
// pending key and the epoch it activates at.
func TestRegisterVRFKeyRegistersTheNewestConfiguredKey(t *testing.T) {
	files, keys, pass := writeVRFKeyFiles(t, t.TempDir(), 1, 2)
	configureRegisterVRFKey(t, files, pass)
	hub := &fakeVRFKeyHub{}

	out, err := executeRegisterVRFKey(t, hub)
	if err != nil {
		t.Fatalf("register-vrf-key: %v\n%s", err, out)
	}
	if len(hub.broadcasts) != 1 {
		t.Fatalf("broadcasts = %d, want 1", len(hub.broadcasts))
	}
	builder := cliTestBuilderAddress()
	msg, err := chaincli.CheckRegisterVrfKeyTx(hub.broadcasts[0], builder)
	if err != nil {
		t.Fatal(err)
	}
	pub := keys[1].Public().(ed25519.PublicKey)
	proof, err := dispatchdraw.ProveVRFKeyPossession(keys[1], vrfCmdHubChainID, builder, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg.GetVrfPubkey(), pub) || msg.GetVrfAuthorizationNonce() != 1 || !bytes.Equal(msg.GetVrfKeyPop(), proof) {
		t.Fatalf("message = %v", msg)
	}
	sum := sha256.Sum256(hub.broadcasts[0])
	want := fmt.Sprintf("builder VRF key registered\nbuilder: %s\nauthority_chain_id: %s\nvrf_pubkey: %x\ntx_hash: %x\n"+
		"vrf_key_status: pending\nactive_vrf_pubkey: none\npending_vrf_pubkey: %x\npending_from_epoch: 7\nvrf_authorization_nonce: 1\n",
		builder, vrfCmdHubChainID, pub, sum, pub)
	if out != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out, want)
	}
	assertNoSecret(t, out, "vrf-secret", hex.EncodeToString(keys[1].Seed()))
}

func TestRegisterVRFKeyUsesTheKeyFileFlag(t *testing.T) {
	dir := t.TempDir()
	files, keys, pass := writeVRFKeyFiles(t, dir, 1, 2)
	configureRegisterVRFKey(t, files[1:], pass)
	hub := &fakeVRFKeyHub{row: &chaincli.VrfKey{ActivePubKey: keys[1].Public().(ed25519.PublicKey), ActiveFromEpoch: 2, AuthorizationNonce: 4}}

	if out, err := executeRegisterVRFKey(t, hub, "--key-file", files[0]); err != nil {
		t.Fatalf("register-vrf-key: %v\n%s", err, out)
	}
	msg, err := chaincli.CheckRegisterVrfKeyTx(hub.broadcasts[0], cliTestBuilderAddress())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg.GetVrfPubkey(), keys[0].Public().(ed25519.PublicKey)) || msg.GetVrfAuthorizationNonce() != 5 {
		t.Fatalf("message = %v; want the --key-file key with nonce 5", msg)
	}
}

// Running the command again once the key is on chain sends nothing and reports the state.
func TestRegisterVRFKeyIsIdempotent(t *testing.T) {
	files, keys, pass := writeVRFKeyFiles(t, t.TempDir(), 1)
	configureRegisterVRFKey(t, files, pass)
	pub := keys[0].Public().(ed25519.PublicKey)
	hub := &fakeVRFKeyHub{row: &chaincli.VrfKey{ActivePubKey: pub, ActiveFromEpoch: 7, AuthorizationNonce: 1}}

	out, err := executeRegisterVRFKey(t, hub)
	if err != nil {
		t.Fatalf("register-vrf-key: %v\n%s", err, out)
	}
	if len(hub.broadcasts) != 0 {
		t.Fatalf("broadcasts = %d, want none", len(hub.broadcasts))
	}
	want := fmt.Sprintf("builder VRF key already registered\nbuilder: %s\nauthority_chain_id: %s\nvrf_pubkey: %x\n"+
		"vrf_key_status: active\nactive_vrf_pubkey: %x\nactive_from_epoch: 7\nvrf_authorization_nonce: 1\n",
		cliTestBuilderAddress(), vrfCmdHubChainID, pub, pub)
	if out != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out, want)
	}
}

func TestRegisterVRFKeyReportsAChainRejection(t *testing.T) {
	files, _, pass := writeVRFKeyFiles(t, t.TempDir(), 1)
	configureRegisterVRFKey(t, files, pass)
	hub := &fakeVRFKeyHub{code: 18, rawLog: "Builder identity is not registered"}

	_, err := executeRegisterVRFKey(t, hub)
	if err == nil || !strings.Contains(err.Error(), "Builder identity is not registered") || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("err = %v", err)
	}
}

func TestRegisterVRFKeyNeedsAKeyAndItsPassword(t *testing.T) {
	files, _, pass := writeVRFKeyFiles(t, t.TempDir(), 1)
	cases := map[string]struct {
		files []string
		pass  string
		args  []string
		want  string
	}{
		"no key file":      {pass: pass, want: "vrf_key_files"},
		"no password file": {files: files, want: "vrf_key_password_file"},
		"missing key file": {pass: pass, args: []string{"--key-file", filepath.Join(t.TempDir(), "missing.keystore")}, want: "missing.keystore"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			configureRegisterVRFKey(t, tc.files, tc.pass)
			hub := &fakeVRFKeyHub{}
			_, err := executeRegisterVRFKey(t, hub, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if len(hub.broadcasts) != 0 {
				t.Fatal("broadcast without a usable key")
			}
		})
	}
}

func TestRootRegistersRegisterVRFKeyCommand(t *testing.T) {
	cmd, _, err := newRootCmd().Find([]string{"builder", "register-vrf-key"})
	if err != nil || cmd.Name() != "register-vrf-key" {
		t.Fatalf("find command: %v, %v", cmd, err)
	}
}
