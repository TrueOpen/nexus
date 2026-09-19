package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TrueOpen/nexus/internal/chaincli"
)

// `builder register` end to end: exactly one MsgRegisterBuilder lands on the Hub (in Phase 0 BuilderBond is
// fixed at zero, so there is no bond transaction) and nothing at all on the Task Chain (the Hub is fail-closed, no fallback is added).
func TestBuilderCommandRegisterTargetsHubAuthority(t *testing.T) {
	taskNode, hubNode, taskGRPC, hubGRPC, stop := startBuilderCommandNodes(t)
	defer stop()
	configureBuilderCommand(t, t.TempDir(), taskGRPC, hubGRPC)

	out, err := executeBuilderCommand("builder", "register")
	if err != nil {
		t.Fatalf("builder register: %v", err)
	}
	if taskNode.broadcasts.Load() != 0 || hubNode.broadcasts.Load() != 1 {
		t.Fatalf("broadcasts task=%d hub=%d, want 0/1", taskNode.broadcasts.Load(), hubNode.broadcasts.Load())
	}
	if got := hubNode.broadcastTypeURLs(); len(got) != 1 || got[0] != chaincli.TypeURLMsgRegisterBuilder {
		t.Fatalf("Hub type URLs = %v, want [%s]", got, chaincli.TypeURLMsgRegisterBuilder)
	}
	assertAuthorityOutput(t, out)
}

// Since wire v0.4.1 there are no Builder bond / unbond subcommands and no pending-bond switch:
// keeping them would make operators believe they can top up or withdraw a bond that does not exist on chain.
func TestBuilderCommandHasNoBondSubcommands(t *testing.T) {
	for _, args := range [][]string{
		{"builder", "bond", "--bond-amount", "250"},
		{"builder", "unbond", "--unbond-amount", "250"},
		{"builder", "register", "--confirm-pending-bond"},
		{"builder", "register", "--retry-pending-bond"},
	} {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			_, err := executeBuilderCommand(args...)
			if err == nil {
				t.Fatalf("%v must not be accepted", args)
			}
		})
	}
}

// With the endpoint config missing, `builder register` must fail before submitting and must not broadcast an empty descriptor.
func TestBuilderCommandRegisterFailsFastWithoutEndpoints(t *testing.T) {
	taskNode, hubNode, taskGRPC, hubGRPC, stop := startBuilderCommandNodes(t)
	defer stop()
	configureBuilderCommand(t, t.TempDir(), taskGRPC, hubGRPC)
	t.Setenv("NEXUS_PUBLIC_ENDPOINT", "")

	_, err := executeBuilderCommand("builder", "register")
	if err == nil || !strings.Contains(err.Error(), "identity.service_endpoints") {
		t.Fatalf("builder register error = %v, want a readable missing-endpoint failure", err)
	}
	if taskNode.broadcasts.Load() != 0 || hubNode.broadcasts.Load() != 0 {
		t.Fatalf("broadcasts task=%d hub=%d, want 0/0", taskNode.broadcasts.Load(), hubNode.broadcasts.Load())
	}
}

func startBuilderCommandNodes(t *testing.T) (taskNode, hubNode *fakeStartNode, taskGRPC, hubGRPC string, stop func()) {
	t.Helper()
	taskNode = &fakeStartNode{accept: true, chainID: "trueopen-task-localnet"}
	taskGRPC, stopTask := startFakeStartNode(t, taskNode)
	hubNode = &fakeStartNode{accept: true, chainID: "trueopen-hub-localnet"}
	hubGRPC, stopHub := startFakeStartNode(t, hubNode)
	return taskNode, hubNode, taskGRPC, hubGRPC, func() {
		stopHub()
		stopTask()
	}
}

func configureBuilderCommand(t *testing.T, dataDir, taskGRPC, hubGRPC string) {
	t.Helper()
	t.Setenv("NEXUS_DATA_DIR", dataDir)
	t.Setenv("NEXUS_LOG_LEVEL", "error")
	t.Setenv("NEXUS_CHAIN_GRPC", taskGRPC)
	t.Setenv("NEXUS_CHAIN_ID", "trueopen-task-localnet")
	t.Setenv("NEXUS_HUB_ENABLED", "true")
	t.Setenv("NEXUS_HUB_GRPC", hubGRPC)
	t.Setenv("NEXUS_HUB_CHAIN_ID", "trueopen-hub-localnet")
	t.Setenv("NEXUS_PRIVATE_KEY_HEX", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	t.Setenv("NEXUS_PUBLIC_ENDPOINT", "https://builder.example:8080")
	t.Setenv("NEXUS_KEYSTORE_FILE", "")
	t.Setenv("NEXUS_KEYSTORE_PASSWORD_FILE", "")
	t.Setenv("NEXUS_KEYSTORE_PASSWORD", "")
	t.Setenv("NEXUS_PRIVATE_KEY", "")
	t.Setenv("NEXUS_PRIVATE_KEY_FILE", "")
}

func executeBuilderCommand(args ...string) (string, error) {
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func assertAuthorityOutput(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "authority_mode: hub") || !strings.Contains(out, "authority_chain_id: trueopen-hub-localnet") {
		t.Fatalf("output missing authority:\n%s", out)
	}
}
