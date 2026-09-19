// Package credential issues and verifies the retrieval credential CredentialV1 (Interface & Topic Catalogue v1.5 §3.2/§3.5).
// A credential is bound to task/recipient/usage/access_level/validity and signed with the Builder private key;
// verification is stateless: nothing is persisted, validity is decided from the signature plus the credential held locally (the same on refresh).
package credential

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/TrueOpen/nexus/internal/signer"
	"github.com/TrueOpen/nexus/internal/types"
)

// Domain separation, so this cannot be confused with other signed objects.
const signDomain = "TRUEOPEN_CREDENTIAL_V1"

var (
	ErrExpired          = errors.New("CREDENTIAL_EXPIRED")
	ErrWrongRecipient   = errors.New("CREDENTIAL_WRONG_RECIPIENT")
	ErrWrongUsage       = errors.New("CREDENTIAL_WRONG_USAGE")
	ErrInvalidSignature = errors.New("CREDENTIAL_UNAUTHORIZED")
)

// SignBytes returns the credential's deterministic sign bytes (length-prefixed concatenation, led by the domain separator). ID is not included -- ID is derived from these bytes.
func SignBytes(c types.Credential) []byte {
	var buf bytes.Buffer
	fields := [][]byte{
		[]byte(signDomain),
		[]byte(c.SessionID),
		[]byte(c.TaskID),
		[]byte(c.Recipient),
		[]byte(c.Usage),
		[]byte(c.AccessLevel.String()),
		i64be(c.ValidUntil),
		[]byte(c.Issuer),
	}
	var l [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		buf.Write(l[:])
		buf.Write(f)
	}
	return buf.Bytes()
}

// Issue completes and issues the credential: it derives ID = hex(sha256(SignBytes)) and signs when signer is non-nil.
// When signer is nil it issues an unsigned credential (dev mode; production must configure signing).
func Issue(sg signer.Signer, c types.Credential) (types.Credential, error) {
	if sg != nil {
		c.Issuer = sg.Address()
	}
	sb := SignBytes(c)
	sum := sha256.Sum256(sb)
	c.ID = hex.EncodeToString(sum[:])
	if sg != nil {
		sig, err := sg.Sign(sb)
		if err != nil {
			return types.Credential{}, err
		}
		c.IssuerSig = sig
	}
	return c, nil
}

// Verify is a stateless check: matching ID + not expired + (when signed) a verifiable signature.
// issuerPub is the issuer's compressed public key (for this node, its own signer's public key); when the credential
// has no signature and issuerPub is empty as well, it is accepted in dev mode (structural check only).
func Verify(c types.Credential, issuerPub []byte, nowMS int64) error {
	sb := SignBytes(c)
	sum := sha256.Sum256(sb)
	if c.ID != hex.EncodeToString(sum[:]) {
		return ErrInvalidSignature // a field was tampered with, the ID no longer matches
	}
	if c.ValidUntil > 0 && nowMS > c.ValidUntil {
		return ErrExpired
	}
	if len(issuerPub) > 0 || len(c.IssuerSig) > 0 {
		if !signer.VerifySig(issuerPub, sb, c.IssuerSig) {
			return ErrInvalidSignature
		}
	}
	return nil
}

func i64be(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	return b[:]
}
