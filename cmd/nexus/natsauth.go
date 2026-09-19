package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/msgbus"
	"github.com/TrueOpen/nexus/internal/natsauth"
)

// The natsauth subcommand is the NATS auth callout service of ADR-0016 decision three:
//
//	nexus natsauth check  -> load the config and the key material, print the identities it would use, connect to nothing
//	nexus natsauth start  -> connect to NATS (AUTH account) and to the chain, subscribe to $SYS.REQ.USER.AUTH and stay resident
//
// It runs on the same machine as NATS and is started by whoever runs NATS; in the transitional state that is the project team, in the target state one per Builder.
func newNATSAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "natsauth",
		Short:         "NATS auth callout service: admit Cortex by its on-chain identity",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newNATSAuthCheckCmd(), newNATSAuthStartCmd())
	return cmd
}

// defaultJetStreamStream is the devnet stream name (§5.13 permission set); check uses it to build the issuer for validation,
// and start uses it as the default value of --jetstream-stream.
const defaultJetStreamStream = "TRUEOPEN_TASK"

type natsAuthMaterial struct {
	cortexSigning nkeys.KeyPair
	authSigning   nkeys.KeyPair
}

// loadNATSAuthMaterial validates the config and reads the two account signing keys; anything missing is an error, no defaults are supplied.
func loadNATSAuthMaterial(cfg config.Config) (natsAuthMaterial, error) {
	if err := cfg.NATSAuth.Validate(); err != nil {
		return natsAuthMaterial{}, err
	}
	if strings.TrimSpace(cfg.Chain.ChainID) == "" || strings.TrimSpace(cfg.Chain.GRPCAddr) == "" {
		return natsAuthMaterial{}, errors.New("natsauth requires chain.chain_id and chain.grpc_addr")
	}
	// The config layer knows xkey_file, but internal/natsauth does not implement response encryption yet: setting it creates
	// the risk of believing responses are encrypted while they are plaintext, so it is rejected fail-closed rather than silently ignored.
	if strings.TrimSpace(cfg.NATSAuth.XKeyFile) != "" {
		return natsAuthMaterial{}, errors.New("natsauth.xkey_file: response encryption is not implemented yet; remove the setting or leave it empty")
	}
	load := func(name, path string) (nkeys.KeyPair, error) {
		seed, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(seed))))
		if err != nil {
			return nil, fmt.Errorf("%s: not an nkey seed: %w", name, err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if !nkeys.IsValidPublicAccountKey(pub) {
			// The first letter of an nkey public key is its type (A = account, U = user, O = operator);
			// the public key should never be empty, but if it really is, report "unknown" rather than indexing out of range.
			prefix := "(unknown)"
			if pub != "" {
				prefix = pub[:1]
			}
			return nil, fmt.Errorf("%s must be an account nkey seed (SA…), but its public key starts with %q, not %q (A = account)", name, prefix, "A")
		}
		return kp, nil
	}
	cortexSigning, err := load("natsauth.cortex_account_signing_key_file", cfg.NATSAuth.CortexAccountSigningKeyFile)
	if err != nil {
		return natsAuthMaterial{}, err
	}
	authSigning, err := load("natsauth.auth_account_signing_key_file", cfg.NATSAuth.AuthAccountSigningKeyFile)
	if err != nil {
		return natsAuthMaterial{}, err
	}
	return natsAuthMaterial{cortexSigning: cortexSigning, authSigning: authSigning}, nil
}

// buildNATSAuthIssuer builds the issuer. check and start share it: the real validity of an nkey (including its checksum)
// is only caught at this step, while the config layer's Validate is just a coarse shape check on length and prefix.
func buildNATSAuthIssuer(cfg config.Config, material natsAuthMaterial, jetStreamStream string) (*natsauth.Issuer, error) {
	// NewIssuer verifies this public key as well, but its error message carries no config key name; checking here first lets
	// the operator see directly which YAML line to fix.
	if !nkeys.IsValidPublicAccountKey(cfg.NATSAuth.CortexAccountPublicKey) {
		return nil, fmt.Errorf("natsauth.cortex_account_public_key %q is not a valid account nkey public key", cfg.NATSAuth.CortexAccountPublicKey)
	}
	return natsauth.NewIssuer(natsauth.IssuerConfig{
		CortexAccountPublicKey: cfg.NATSAuth.CortexAccountPublicKey,
		CortexSigningKey:       material.cortexSigning,
		AuthSigningKey:         material.authSigning,
		JetStreamStream:        jetStreamStream,
		UserJWTTTL:             time.Duration(cfg.NATSAuth.UserJWTTTLMS) * time.Millisecond,
	})
}

// buildNATSAuthService assembles the config into a startable service; connect is injected by the caller so tests do not connect to NATS.
func buildNATSAuthService(cfg config.Config, log *slog.Logger, jetStreamStream string, connect func(context.Context) (*nats.Conn, error)) (*natsauth.Service, error) {
	material, err := loadNATSAuthMaterial(cfg)
	if err != nil {
		return nil, err
	}
	issuer, err := buildNATSAuthIssuer(cfg, material, jetStreamStream)
	if err != nil {
		return nil, err
	}
	chain := chaincli.New(log, cfg.Chain)
	verifier := natsauth.NewVerifier(natsauth.VerifierConfig{
		ChainID:      cfg.Chain.ChainID,
		Chain:        natsauth.NewCachedChain(chain, time.Duration(cfg.NATSAuth.ChainQueryCacheTTLMS)*time.Millisecond, time.Now),
		MaxClockSkew: time.Duration(cfg.NATSAuth.MaxClockSkewMS) * time.Millisecond,
	})
	return natsauth.NewService(natsauth.ServiceConfig{Log: log, Verifier: verifier, Issuer: issuer, Connect: connect})
}

// natsAuthConnector connects to NATS with the AUTH account's creds; reconnects are unlimited, so it recovers on its own after a disconnect.
// The context in the signature is deliberately unused: nats.Connect has no ctx-taking variant, and the connect timeout can only be
// controlled through nats.Timeout. The parameter is kept to match natsauth.ServiceConfig.Connect.
func natsAuthConnector(cfg config.NATSConfig) func(context.Context) (*nats.Conn, error) {
	return func(context.Context) (*nats.Conn, error) {
		opts, err := msgbus.ConnectOptions(cfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.Name("nexus-natsauth"), nats.Timeout(5*time.Second), nats.MaxReconnects(-1))
		return nats.Connect(strings.Join(cfg.Servers, ","), opts...)
	}
}

func newNATSAuthCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "check",
		Short:         "Validate natsauth configuration and key material without connecting",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cfgFrom(cmd)
			material, err := loadNATSAuthMaterial(cfg)
			if err != nil {
				return err
			}
			cortexPub, err := material.cortexSigning.PublicKey()
			if err != nil {
				return err
			}
			authPub, err := material.authSigning.PublicKey()
			if err != nil {
				return err
			}
			// Build the issuer once: the value of check is to surface errors that would otherwise only blow up at start,
			// including the real nkey validation of the application account (TRUEOPEN) public key (an A... string with a bad checksum is rejected here).
			if _, err := buildNATSAuthIssuer(cfg, material, defaultJetStreamStream); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"chain_id: %s\nchain_grpc: %s\nnats_servers: %s\ncortex_account_public_key: %s\ncortex_signing_key: %s\nauth_signing_key: %s\nuser_jwt_ttl_ms: %d\nchain_query_cache_ttl_ms: %d\nmax_clock_skew_ms: %d\nxkey_file: %s\nauth_subject: %s\n",
				cfg.Chain.ChainID, cfg.Chain.GRPCAddr, strings.Join(cfg.NATSAuth.NATS.Servers, ","),
				cfg.NATSAuth.CortexAccountPublicKey, cortexPub, authPub,
				cfg.NATSAuth.UserJWTTTLMS, cfg.NATSAuth.ChainQueryCacheTTLMS, cfg.NATSAuth.MaxClockSkewMS,
				// By this point xkey_file is necessarily empty -- see the "response encryption is not implemented yet"
				// rejection in loadNATSAuthMaterial; it is still printed so operators can see at a glance that response
				// encryption is off.
				"(unset)", natsauth.AuthSubject)
			return nil
		},
	}
}

func newNATSAuthStartCmd() *cobra.Command {
	var jetStreamStream string
	cmd := &cobra.Command{
		Use:           "start",
		Short:         "Run the auth callout service",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cfgFrom(cmd)
			log := logFrom(cmd)
			svc, err := buildNATSAuthService(cfg, log, jetStreamStream, natsAuthConnector(cfg.NATSAuth.NATS))
			if err != nil {
				return err
			}
			parent := cmd.Context()
			if parent == nil {
				parent = context.Background()
			}
			ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := svc.Start(ctx); err != nil {
				return err
			}
			<-ctx.Done()
			log.Info("natsauth: shutdown signal received")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return svc.Stop(shutdownCtx)
		},
	}
	cmd.Flags().StringVar(&jetStreamStream, "jetstream-stream", defaultJetStreamStream, "JetStream stream name written into the CORTEX permission set")
	return cmd
}
