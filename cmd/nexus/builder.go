package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/builderreg"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/dispatchdraw"
	"github.com/TrueOpen/nexus/internal/identity"
	"github.com/TrueOpen/nexus/internal/ingresstls"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

// builderCommandDeps are the outside dependencies of the builder subcommands that tests replace.
type builderCommandDeps struct {
	newChain func(*slog.Logger, config.ChainConfig) chaincli.Client
}

func newBuilderCmd() *cobra.Command {
	return newBuilderCmdWithDeps(builderCommandDeps{
		newChain: func(log *slog.Logger, cfg config.ChainConfig) chaincli.Client { return chaincli.New(log, cfg) },
	})
}

func newBuilderCmdWithDeps(deps builderCommandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "builder",
		Short: "Builder registration operations",
	}
	// There is no BuilderBond (the staking and slashing protocol fixes it at zero and creates no bonded stake record),
	// and wire has no Builder bond / unbond messages either, so there are no bond subcommands.
	cmd.AddCommand(newBuilderRegisterCmd(), newBuilderRegisterVRFKeyCmd(deps))
	return cmd
}

func newBuilderRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Ensure this Builder is registered on the authority chain with the current service descriptor",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cfgFrom(cmd)
			log := logFrom(cmd)
			sg, authority, err := builderCommandIdentity(cfg)
			if err != nil {
				return err
			}
			store, err := kv.NewPebble(filepath.Join(cfg.DataDir, "kv"), log)
			if err != nil {
				return fmt.Errorf("builder registration store: %w", err)
			}
			defer func() { _ = store.Close() }()

			chain := chaincli.New(log, authority.Chain)
			serviceSG, sharedServiceKey, err := identity.LoadServiceSigner(cfg.Identity, sg)
			if err != nil {
				return err
			}
			if sharedServiceKey {
				log.Warn("builder account and service signatures share one key")
			}
			// Uses the same certificate as nexus start: the tls_pubkey_hash in the descriptor must equal
			// the public key the ingress actually presents, otherwise the client-side check fails.
			if err := cfg.ValidateTransport(); err != nil {
				return err
			}
			tlsMaterial, err := ingresstls.LoadOrCreate(cfg.Ingress.TLS, cfg.DataDir, ingresstls.HostsFromEndpoint(cfg.Identity.PublicEndpoint))
			if err != nil {
				return err
			}
			reg := builderreg.New(
				log,
				store,
				chain,
				coordinator.NewBuilderSubmitter(log, chain, sg, authority.Chain),
				sg,
				serviceSG,
				cfg.Identity,
				authority,
				builderreg.WithTLSPubKeyHash(tlsMaterial.PubKeyHash),
			)
			if err := reg.Ensure(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "builder registration ensured\nbuilder: %s\nauthority_mode: %s\nauthority_chain_id: %s\n",
				sg.Address(), authority.Mode, authority.Chain.ChainID)
			if tlsMaterial.Enabled() {
				fmt.Fprintf(cmd.OutOrStdout(), "tls_pubkey_hash: %s\n", tlsMaterial.PubKeyHash)
			}
			return nil
		},
	}
	return cmd
}

func newBuilderRegisterVRFKeyCmd(deps builderCommandDeps) *cobra.Command {
	var keyFile string
	cmd := &cobra.Command{
		Use:   "register-vrf-key",
		Short: "Ensure the authority chain holds this Builder's VRF key (active, or pending until the next epoch)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cfgFrom(cmd)
			log := logFrom(cmd)
			key, err := builderVRFKey(cfg.Identity, keyFile)
			if err != nil {
				return err
			}
			sg, authority, err := builderCommandIdentity(cfg)
			if err != nil {
				return err
			}
			chain := deps.newChain(log, authority.Chain)
			txs, ok := chain.(chaincli.TxQuerier)
			if !ok {
				return fmt.Errorf("authority chain client cannot read transaction results")
			}
			outcome, err := builderreg.RegisterVRFKey(cmd.Context(), builderreg.VRFKeyRegistration{
				ChainID: authority.Chain.ChainID,
				Builder: sg.Address(),
				Key:     key,
				Chain:   vrfKeyHub{Client: chain, TxQuerier: txs},
				Submit:  coordinator.NewVRFKeySubmitter(log, chain, sg, authority.Chain),
				Log:     log,
			})
			if err != nil {
				return err
			}
			printVRFKeyOutcome(cmd.OutOrStdout(), sg.Address(), authority.Chain.ChainID, key, outcome)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyFile, "key-file", "", "VRF key file to register (default: the last entry of identity.vrf_key_files); its password is identity.vrf_key_password_file")
	return cmd
}

// builderVRFKey loads the VRF key to register: keyFile, or else the newest configured key (the
// last entry of identity.vrf_key_files).
func builderVRFKey(identity config.IdentityConfig, keyFile string) (ed25519.PrivateKey, error) {
	path := strings.TrimSpace(keyFile)
	if path == "" {
		if len(identity.VRFKeyFiles) == 0 {
			return nil, fmt.Errorf("no VRF key to register: set identity.vrf_key_files (NEXUS_VRF_KEY_FILES) or pass --key-file")
		}
		path = identity.VRFKeyFiles[len(identity.VRFKeyFiles)-1]
	}
	if strings.TrimSpace(identity.VRFKeyPasswordFile) == "" {
		return nil, fmt.Errorf("identity.vrf_key_password_file (NEXUS_VRF_KEY_PASSWORD_FILE) is required to read the VRF key")
	}
	keys, err := dispatchdraw.LoadVRFKeys([]string{path}, identity.VRFKeyPasswordFile)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}

// vrfKeyHub joins the chain client with its transaction result reader.
type vrfKeyHub struct {
	chaincli.Client
	chaincli.TxQuerier
}

func printVRFKeyOutcome(w io.Writer, builder, chainID string, key ed25519.PrivateKey, outcome builderreg.VRFKeyOutcome) {
	if outcome.Submitted {
		fmt.Fprintln(w, "builder VRF key registered")
	} else {
		fmt.Fprintln(w, "builder VRF key already registered")
	}
	fmt.Fprintf(w, "builder: %s\nauthority_chain_id: %s\nvrf_pubkey: %x\n", builder, chainID, []byte(key.Public().(ed25519.PublicKey)))
	if outcome.Submitted {
		fmt.Fprintf(w, "tx_hash: %x\n", outcome.TxHash)
	}
	fmt.Fprintf(w, "vrf_key_status: %s\n", outcome.Status)
	state := outcome.State
	if len(state.ActivePubKey) == 0 {
		fmt.Fprintln(w, "active_vrf_pubkey: none")
	} else {
		fmt.Fprintf(w, "active_vrf_pubkey: %x\nactive_from_epoch: %d\n", state.ActivePubKey, state.ActiveFromEpoch)
	}
	if state.PendingPubKey != nil {
		fmt.Fprintf(w, "pending_vrf_pubkey: %x\npending_from_epoch: %d\n", state.PendingPubKey, state.PendingFromEpoch)
	}
	fmt.Fprintf(w, "vrf_authorization_nonce: %d\n", state.AuthorizationNonce)
}

func builderCommandIdentity(cfg config.Config) (signer.Signer, config.BuilderAuthority, error) {
	authority, err := cfg.BuilderAuthority()
	if err != nil {
		return nil, config.BuilderAuthority{}, err
	}
	sg, err := identity.LoadSigner(cfg.Identity)
	if err != nil {
		return nil, config.BuilderAuthority{}, err
	}
	if sg == nil {
		return nil, config.BuilderAuthority{}, fmt.Errorf("builder signer is required (NEXUS_KEYSTORE_FILE, NEXUS_PRIVATE_KEY_FILE, NEXUS_PRIVATE_KEY, or NEXUS_PRIVATE_KEY_HEX)")
	}
	if _, err := identity.ResolveBuilderAddress(cfg.Identity, sg); err != nil {
		return nil, config.BuilderAuthority{}, err
	}
	return sg, authority, nil
}
