package chaincli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	taskv1 "github.com/TrueOpen/nexus/gen/trueopen/task/v1"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/nodecontract"
)

const remoteReadOnlyTimeout = 10 * time.Second

func TestRemoteNodeReadOnlyIntegration(t *testing.T) {
	t.Run("grpc_latest_height", func(t *testing.T) {
		grpcAddr := os.Getenv("NEXUS_CHAIN_IT_GRPC")
		chainID := os.Getenv("NEXUS_CHAIN_IT_CHAIN_ID")
		if grpcAddr == "" || chainID == "" {
			t.Skip("set NEXUS_CHAIN_IT_GRPC and NEXUS_CHAIN_IT_CHAIN_ID to run grpc_latest_height")
		}
		c, ok := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.ChainConfig{
			GRPCAddr: grpcAddr, ChainID: chainID,
		}).(*client)
		if !ok {
			t.Fatal("New did not return the real chain client")
		}
		ctx, cancel := context.WithTimeout(context.Background(), remoteReadOnlyTimeout)
		defer cancel()
		height, err := c.LatestHeight(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if height == 0 {
			t.Fatal("latest height is zero")
		}
	})

	t.Run("grpc_task", func(t *testing.T) {
		grpcAddr := os.Getenv("NEXUS_CHAIN_IT_GRPC")
		sessionID := os.Getenv("NEXUS_CHAIN_IT_SESSION_ID")
		taskID := os.Getenv("NEXUS_CHAIN_IT_TASK_ID")
		if grpcAddr == "" || sessionID == "" || taskID == "" {
			t.Skip("set NEXUS_CHAIN_IT_GRPC, NEXUS_CHAIN_IT_SESSION_ID, and NEXUS_CHAIN_IT_TASK_ID to run grpc_task")
		}

		c, err := newIntegrationClient(grpcAddr)
		if err != nil {
			t.Fatal(err)
		}

		// Frozen contract: QueryTask queries by task_id (Hash32 bytes) only and returns TaskViewV1.
		taskKey, err := nodecontract.Hash32Bytes("task_id", taskID)
		if err != nil {
			t.Fatalf("NEXUS_CHAIN_IT_TASK_ID must be canonical 64-hex: %v", err)
		}
		rawCtx, cancel := context.WithTimeout(context.Background(), remoteReadOnlyTimeout)
		defer cancel()
		raw, err := c.taskQuery.Task(rawCtx, connect.NewRequest(&taskv1.QueryTaskRequest{TaskId: taskKey}))
		if err != nil {
			t.Fatalf("raw query task: %v", err)
		}
		if raw.Msg == nil {
			t.Fatal("raw query task: empty message")
		}
		if got := hex.EncodeToString(raw.Msg.GetTask().GetActive().GetCore().GetTaskId()); got != taskID {
			t.Fatalf("raw task_id=%q want %q", got, taskID)
		}

		publicCtx, cancel := context.WithTimeout(context.Background(), remoteReadOnlyTimeout)
		defer cancel()
		got, err := c.QueryTask(publicCtx, TaskKey{
			SessionID: sessionID,
			TaskID:    taskID,
		})
		if err != nil {
			t.Fatalf("public query task: %v", err)
		}
		if got.TaskID != taskID {
			t.Fatalf("public task_id=%q want %q", got.TaskID, taskID)
		}
	})

	t.Run("rest_node_info", func(t *testing.T) {
		restAddr := os.Getenv("NEXUS_CHAIN_IT_REST")
		chainID := os.Getenv("NEXUS_CHAIN_IT_CHAIN_ID")
		if restAddr == "" || chainID == "" {
			t.Skip("set NEXUS_CHAIN_IT_REST and NEXUS_CHAIN_IT_CHAIN_ID to run rest_node_info")
		}

		ctx, cancel := context.WithTimeout(context.Background(), remoteReadOnlyTimeout)
		defer cancel()
		got, err := queryRESTNodeInfo(ctx, restBaseURL(restAddr))
		if err != nil {
			t.Fatal(err)
		}
		if got != chainID {
			t.Fatalf("network=%q want %q", got, chainID)
		}
	})

	t.Run("rest_latest_block", func(t *testing.T) {
		restAddr := os.Getenv("NEXUS_CHAIN_IT_REST")
		chainID := os.Getenv("NEXUS_CHAIN_IT_CHAIN_ID")
		if restAddr == "" || chainID == "" {
			t.Skip("set NEXUS_CHAIN_IT_REST and NEXUS_CHAIN_IT_CHAIN_ID to run rest_latest_block")
		}

		ctx, cancel := context.WithTimeout(context.Background(), remoteReadOnlyTimeout)
		defer cancel()
		gotChainID, gotHeight, err := queryRESTLatestBlock(ctx, restBaseURL(restAddr))
		if err != nil {
			t.Fatal(err)
		}
		if gotChainID != chainID {
			t.Fatalf("chain_id=%q want %q", gotChainID, chainID)
		}
		if gotHeight == "" {
			t.Fatal("latest block height is empty")
		}
	})

	t.Run("grpc_events", func(t *testing.T) {
		grpcAddr := os.Getenv("NEXUS_CHAIN_IT_GRPC")
		sessionID := os.Getenv("NEXUS_CHAIN_IT_SESSION_ID")
		taskID := os.Getenv("NEXUS_CHAIN_IT_TASK_ID")
		if grpcAddr == "" || sessionID == "" || taskID == "" {
			t.Skip("set NEXUS_CHAIN_IT_GRPC, NEXUS_CHAIN_IT_SESSION_ID, and NEXUS_CHAIN_IT_TASK_ID to run grpc_events")
		}
		c, err := newIntegrationClient(grpcAddr)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), remoteReadOnlyTimeout)
		defer cancel()
		sessionKey, err := nodecontract.Hash32Bytes("session_id", sessionID)
		if err != nil {
			t.Fatalf("NEXUS_CHAIN_IT_SESSION_ID must be canonical 64-hex: %v", err)
		}
		taskKey, err := nodecontract.Hash32Bytes("task_id", taskID)
		if err != nil {
			t.Fatalf("NEXUS_CHAIN_IT_TASK_ID must be canonical 64-hex: %v", err)
		}
		stream, err := c.taskEvents.SubscribeTaskEvents(ctx, connect.NewRequest(&taskv1.SubscribeTaskEventsRequest{
			SessionId:  sessionKey,
			TaskId:     taskKey,
			FromHeight: 1,
		}))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = stream.Close() }()
		if !stream.Receive() {
			t.Fatalf("no task event received: %v", stream.Err())
		}
		event := stream.Msg().GetEvent()
		if event == nil || event.GetChainHeight() == 0 ||
			hex.EncodeToString(event.GetSessionId()) != sessionID || hex.EncodeToString(event.GetTaskId()) != taskID {
			t.Fatalf("invalid task event: %+v", stream.Msg())
		}
	})
}

func newIntegrationClient(grpcAddr string) (*client, error) {
	c, ok := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.ChainConfig{
		GRPCAddr: grpcAddr,
		ChainID:  "integration-localnet",
	}).(*client)
	if !ok {
		return nil, fmt.Errorf("New returned %T, want *client", c)
	}
	return c, nil
}

func queryRESTNodeInfo(ctx context.Context, restURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, restURL+"/cosmos/base/tendermint/v1beta1/node_info", nil)
	if err != nil {
		return "", fmt.Errorf("build REST node_info request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("get REST node_info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", responseStatusError("REST node_info", resp)
	}

	var decoded struct {
		DefaultNodeInfo struct {
			Network string `json:"network"`
		} `json:"default_node_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", fmt.Errorf("decode REST node_info response: %w", err)
	}
	if decoded.DefaultNodeInfo.Network == "" {
		return "", fmt.Errorf("empty default_node_info.network")
	}
	return decoded.DefaultNodeInfo.Network, nil
}

func queryRESTLatestBlock(ctx context.Context, restURL string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, restURL+"/cosmos/base/tendermint/v1beta1/blocks/latest", nil)
	if err != nil {
		return "", "", fmt.Errorf("build REST latest block request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("get REST latest block: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", responseStatusError("REST latest block", resp)
	}

	var decoded struct {
		Block struct {
			Header struct {
				ChainID string `json:"chain_id"`
				Height  string `json:"height"`
			} `json:"header"`
		} `json:"block"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", "", fmt.Errorf("decode REST latest block response: %w", err)
	}
	if decoded.Block.Header.ChainID == "" {
		return "", "", fmt.Errorf("empty block.header.chain_id")
	}
	return decoded.Block.Header.ChainID, decoded.Block.Header.Height, nil
}

func restBaseURL(addr string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(addr), "/")
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	return "http://" + trimmed
}

func responseStatusError(name string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	detail := strings.TrimSpace(string(body))
	if detail == "" {
		return fmt.Errorf("%s HTTP %d", name, resp.StatusCode)
	}
	return fmt.Errorf("%s HTTP %d: %s", name, resp.StatusCode, detail)
}
