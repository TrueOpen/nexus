package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/TrueOpen/nexus/internal/config"
	"github.com/TrueOpen/nexus/internal/ingresstls"
)

// The tls subcommand is the first step of the ADR-0015 registration order:
//
//	nexus tls init                -> create the self-signed certificate, print the public-key fingerprint (tls_pubkey_hash)
//	nexus builder register        -> the operator writes the https endpoint + fingerprint into the descriptor with the operator key
//	nexus start (ingress.tls.enabled=true) -> only loads the certificate and checks it against the on-chain fingerprint; never touches the descriptor
//
// Neither subcommand looks at ingress.tls.enabled: the operator must have the certificate and the fingerprint before enabling TLS.
func newTLSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "tls",
		Short:         "Ingress TLS certificate operations",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newTLSInitCmd(), newTLSFingerprintCmd())
	return cmd
}

func tlsConfigForced(cfg config.Config) config.IngressTLSConfig {
	forced := cfg.Ingress.TLS
	forced.Enabled = true
	return forced
}

func printTLSMaterial(cmd *cobra.Command, cfg config.Config, material ingresstls.Material) {
	certFile, keyFile := ingresstls.Paths(tlsConfigForced(cfg), cfg.DataDir)
	fmt.Fprintf(cmd.OutOrStdout(), "cert_file: %s\nkey_file: %s\nnot_after: %s\ntls_pubkey_hash: %s\n",
		certFile, keyFile, material.Leaf.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), material.PubKeyHash)
}

func newTLSInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "init",
		Short:         "Create the self-signed ingress certificate if absent and print its public-key fingerprint",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cfgFrom(cmd)
			material, err := ingresstls.LoadOrCreate(tlsConfigForced(cfg), cfg.DataDir,
				ingresstls.HostsFromEndpoint(cfg.Identity.PublicEndpoint))
			if err != nil {
				return err
			}
			printTLSMaterial(cmd, cfg, material)
			fmt.Fprintln(cmd.OutOrStdout(), "next: register the fingerprint with `nexus builder register` (operator key), then enable ingress.tls and start")
			return nil
		},
	}
}

func newTLSFingerprintCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "fingerprint",
		Short:         "Print the public-key fingerprint (tls_pubkey_hash) of the existing ingress certificate",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := cfgFrom(cmd)
			material, err := ingresstls.Load(tlsConfigForced(cfg), cfg.DataDir)
			if err != nil {
				return err
			}
			printTLSMaterial(cmd, cfg, material)
			return nil
		},
	}
}
