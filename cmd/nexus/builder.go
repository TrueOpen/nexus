package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/builderreg"
	"github.com/TrueOpen/nexus/internal/chaincli"
	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/coordinator"
	"github.com/TrueOpen/nexus/internal/identity"
	"github.com/TrueOpen/nexus/internal/ingresstls"
	"github.com/TrueOpen/nexus/internal/kv"
	"github.com/TrueOpen/nexus/internal/signer"
)

func newBuilderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "builder",
		Short: "Builder registration operations",
	}
	// Phase 0 has no BuilderBond (the staking and slashing protocol fixes it at zero and creates no bonded stake record),
	// and wire v0.4.1 has no Builder bond / unbond messages either, so register is the only subcommand.
	cmd.AddCommand(newBuilderRegisterCmd())
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
