package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/ops"
)

// The drain subcommand runs a service key rotation without charging failed records to this
// Builder. It talks to the running daemon through <data_dir>/ops (no network listener): the
// request file it leaves is taken on the daemon's next tick, and the daemon's status file says
// where the drain stands.
//
//	nexus drain begin   -> no new order, ticket or takeover; in-flight work finishes
//	nexus drain status  -> wait for phase DRAINED (nothing remains), then submit the rotation
//	                       with the operator key; ROTATION_PENDING until it activates
//	restart nexus with the new service key -> the drain ends by itself (or: nexus drain end)
func newDrainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "drain",
		Short:         "Drain the running Builder before a service key rotation",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newDrainRequestCmd(ops.DrainBegin, "Stop taking new orders, tickets and takeovers; in-flight work finishes"),
		newDrainRequestCmd(ops.DrainEnd, "End the drain: new orders are taken again"),
		newDrainStatusCmd())
	return cmd
}

func newDrainRequestCmd(request, short string) *cobra.Command {
	var wait time.Duration
	cmd := &cobra.Command{
		Use:           request,
		Short:         short,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dataDir := cfgFrom(cmd).DataDir
			requested := time.Now()
			if err := ops.WriteDrainRequest(dataDir, request); err != nil {
				return err
			}
			status, outcome := waitForStatusAfter(dataDir, requested, wait)
			switch outcome {
			case requestNotTaken:
				fmt.Fprintf(cmd.OutOrStdout(), "drain %s requested in %s; the daemon has not taken it yet (is it running?); it is applied at its next start\n",
					request, ops.DrainRequestPath(dataDir))
				return nil
			case requestTaken:
				fmt.Fprintf(cmd.OutOrStdout(), "drain %s: the daemon took the request but has not written its status since; check `nexus drain status`\n", request)
				return nil
			}
			return printDrain(cmd, status)
		},
	}
	cmd.Flags().DurationVar(&wait, "wait", 15*time.Second, "how long to wait for the running daemon to take the request")
	return cmd
}

func newDrainStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "status",
		Short:         "Print the drain phase and the work that remains, as the daemon last wrote it",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			status, err := readStatus(cfgFrom(cmd).DataDir)
			if err != nil {
				return err
			}
			return printDrain(cmd, status)
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "status",
		Short:         "Print the running Builder's readiness, diagnostics, drain and metrics, as the daemon last wrote them",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := ops.ReadStatus(cfgFrom(cmd).DataDir)
			if err != nil {
				return statusErr(err)
			}
			var s statusView
			if json.Unmarshal(raw, &s) == nil {
				warnStale(cmd, s)
			}
			_, err = cmd.OutOrStdout().Write(raw)
			return err
		},
	}
}

// statusView is the part of the status file the drain commands read.
type statusView struct {
	WrittenAt time.Time       `json:"written_at"`
	Drain     json.RawMessage `json:"drain"`
}

func readStatus(dataDir string) (statusView, error) {
	raw, err := ops.ReadStatus(dataDir)
	if err != nil {
		return statusView{}, statusErr(err)
	}
	var s statusView
	if err := json.Unmarshal(raw, &s); err != nil {
		return statusView{}, fmt.Errorf("status file %s: %w", ops.StatusPath(dataDir), err)
	}
	return s, nil
}

func statusErr(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no status file yet: the daemon writes it once it runs (%w)", err)
	}
	return err
}

// How far the daemon got with a request when the wait ended.
const (
	requestNotTaken = iota
	requestTaken
	statusWritten
)

// waitForStatusAfter waits until the daemon took the request and wrote its status after since.
func waitForStatusAfter(dataDir string, since time.Time, wait time.Duration) (statusView, int) {
	deadline := time.Now().Add(wait)
	for {
		outcome := requestNotTaken
		if _, err := os.Stat(ops.DrainRequestPath(dataDir)); errors.Is(err, os.ErrNotExist) {
			outcome = requestTaken
			if s, err := readStatus(dataDir); err == nil && s.WrittenAt.After(since) {
				return s, statusWritten
			}
		}
		if !time.Now().Before(deadline) {
			return statusView{}, outcome
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// warnStale warns when the status file was not rewritten for several ticks.
func warnStale(cmd *cobra.Command, s statusView) {
	if age := time.Since(s.WrittenAt); age > ops.StatusStaleAfter {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: the status was written %s ago; the daemon may not be running\n", age.Round(time.Second))
	}
}

func printDrain(cmd *cobra.Command, s statusView) error {
	if len(s.Drain) == 0 || string(s.Drain) == "null" {
		return errors.New("this Builder does not dispatch: there is nothing to drain")
	}
	warnStale(cmd, s)
	fmt.Fprintf(cmd.OutOrStdout(), "written_at: %s\n", s.WrittenAt.UTC().Format(time.RFC3339))
	var pretty map[string]any
	if err := json.Unmarshal(s.Drain, &pretty); err != nil {
		return err
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", out)
	return err
}
