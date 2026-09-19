package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/TrueOpen/nexus/internal/signer"
)

type secretReader func(*cobra.Command, string) ([]byte, error)

type keysCommandDeps struct {
	readSecret   secretReader
	writeFile    func(string, []byte) error
	bech32Prefix func(*cobra.Command) string
}

func newKeysCmd() *cobra.Command {
	return newKeysCmdWithDeps(keysCommandDeps{
		readSecret: readSecretFromTerminal,
		writeFile:  writeNewKeystoreFile,
		bech32Prefix: func(cmd *cobra.Command) string {
			return cfgFrom(cmd).Identity.Bech32Prefix
		},
	})
}

func newKeysCmdWithDeps(deps keysCommandDeps) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "keys",
		Short:         "Key management operations",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newCreateKeystoreCmd(deps))
	return cmd
}

func newCreateKeystoreCmd(deps keysCommandDeps) *cobra.Command {
	var privateKeyFile, output string
	cmd := &cobra.Command{
		Use:           "create-keystore",
		Short:         "Encrypt a raw secp256k1 private key as a Cosmos keystore",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := readPrivateKey(cmd, privateKeyFile, deps.readSecret)
			if err != nil {
				return err
			}
			password, err := readConfirmedPassword(cmd, deps.readSecret)
			if err != nil {
				return err
			}
			armored, err := signer.EncryptKeystoreArmor(raw, password)
			if err != nil {
				return err
			}
			account, err := signer.NewFromBytes(raw, deps.bech32Prefix(cmd))
			if err != nil {
				return fmt.Errorf("derive keystore address: %w", err)
			}
			if err := deps.writeFile(output, armored); err != nil {
				return fmt.Errorf("write keystore %q: %w", output, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "keystore: %s\naddress: %s\n", output, account.Address())
			return nil
		},
	}
	cmd.Flags().StringVar(&privateKeyFile, "private-key-file", "", "file containing a 32-byte hex private key; omit for hidden terminal input")
	cmd.Flags().StringVar(&output, "output", "builder.keystore", "new keystore output path")
	return cmd
}

func readPrivateKey(cmd *cobra.Command, path string, readSecret secretReader) ([]byte, error) {
	var value []byte
	var err error
	if strings.TrimSpace(path) == "" {
		value, err = readSecret(cmd, "Private key: ")
	} else {
		value, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read private key file %q: %w", path, err)
		}
	}
	if err != nil {
		return nil, err
	}
	return signer.ParsePrivateKeyHex(string(value))
}

func readConfirmedPassword(cmd *cobra.Command, readSecret secretReader) ([]byte, error) {
	password, err := readSecret(cmd, "Keystore password: ")
	if err != nil {
		return nil, err
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("keystore password must not be empty")
	}
	confirmation, err := readSecret(cmd, "Confirm keystore password: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(password, confirmation) {
		return nil, fmt.Errorf("keystore passwords do not match")
	}
	return password, nil
}

func readSecretFromTerminal(cmd *cobra.Command, prompt string) ([]byte, error) {
	in, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(in.Fd())) {
		return nil, fmt.Errorf("attached terminal required for hidden input")
	}
	if _, err := fmt.Fprint(cmd.ErrOrStderr(), prompt); err != nil {
		return nil, fmt.Errorf("write secret prompt: %w", err)
	}
	value, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return nil, fmt.Errorf("read hidden terminal input: %w", err)
	}
	return value, nil
}

type syncWriteCloser interface {
	io.Writer
	Sync() error
	Close() error
}

type exclusiveOpener func(string, int, os.FileMode) (syncWriteCloser, error)

func writeNewKeystoreFile(path string, data []byte) error {
	return writeNewKeystoreFileWith(path, data, func(name string, flag int, perm os.FileMode) (syncWriteCloser, error) {
		return os.OpenFile(name, flag, perm)
	}, os.Remove)
}

func writeNewKeystoreFileWith(path string, data []byte, open exclusiveOpener, remove func(string) error) (err error) {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("keystore output path is required")
	}
	f, err := open(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if complete {
			return
		}
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close incomplete keystore %q: %w", path, closeErr))
		}
		if removeErr := remove(path); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove incomplete keystore %q: %w", path, removeErr))
		}
	}()
	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}
