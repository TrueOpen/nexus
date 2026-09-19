package natsauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// MaxUserJWTTTL is the user JWT TTL upper bound of §5.14.3 (3,600,000 ms).
const MaxUserJWTTTL = time.Hour

// genericFailureDetail is the detail written into the response for the non-RejectError fallback: no internal error text leaks.
const genericFailureDetail = "request could not be processed"

// IssuerConfig is the issuer's deployment-side input: two account keys plus permission set parameters.
type IssuerConfig struct {
	// CortexAccountPublicKey is the public key of the application account (TRUEOPEN, shared with nexus) Cortex users land in: the user JWT aud, and issuer_account when a signing key is used.
	CortexAccountPublicKey string
	// CortexSigningKey is that application account's (TRUEOPEN) signing key (account-type nkey); it signs Cortex user JWTs.
	CortexSigningKey nkeys.KeyPair
	// AuthSigningKey is the AUTH account's key (account-type nkey); it signs the authorization response.
	AuthSigningKey nkeys.KeyPair
	// JetStreamStream enters the permission set (§5.13); TRUEOPEN_TASK on devnet.
	JetStreamStream string
	// UserJWTTTL is the user JWT validity period; must fall in (0, MaxUserJWTTTL].
	UserJWTTTL time.Duration
}

// Issuer generates JWTs per the "issue" and "response" tables of §5.14.3.
type Issuer struct {
	cfg IssuerConfig
	// cortexSigningPub is the public key of CortexSigningKey, computed once at construction:
	// every issue compares it with the account public key to decide whether to write issuer_account.
	cortexSigningPub string
}

// accountSigningPub extracts the public key of an account signing key and confirms it can actually sign:
// it must be an account-type nkey and yield a seed (a public-only KeyPair cannot sign).
func accountSigningPub(name string, kp nkeys.KeyPair) (string, error) {
	if kp == nil {
		return "", fmt.Errorf("natsauth: %s is required", name)
	}
	pub, err := kp.PublicKey()
	if err != nil || !nkeys.IsValidPublicAccountKey(pub) {
		return "", fmt.Errorf("natsauth: %s must be an account nkey", name)
	}
	if _, err := kp.Seed(); err != nil {
		return "", fmt.Errorf("natsauth: %s must carry its seed to sign", name)
	}
	return pub, nil
}

// NewIssuer validates the deployment config and constructs the issuer: a bad config refuses to start rather than failing at issue time.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	switch {
	case !nkeys.IsValidPublicAccountKey(cfg.CortexAccountPublicKey):
		return nil, errors.New("natsauth: cortex account public key is not an account nkey")
	case strings.TrimSpace(cfg.JetStreamStream) == "":
		return nil, errors.New("natsauth: jetstream stream name is required for the permission set")
	case cfg.UserJWTTTL <= 0 || cfg.UserJWTTTL > MaxUserJWTTTL:
		return nil, fmt.Errorf("natsauth: user jwt ttl must be within (0, %s]", MaxUserJWTTTL)
	}
	cortexSigningPub, err := accountSigningPub("cortex signing key", cfg.CortexSigningKey)
	if err != nil {
		return nil, err
	}
	if _, err := accountSigningPub("auth signing key", cfg.AuthSigningKey); err != nil {
		return nil, err
	}
	return &Issuer{cfg: cfg, cortexSigningPub: cortexSigningPub}, nil
}

// UserJWT issues a short-lived user JWT: sub = server-assigned user_nkey, name = cortex:<operator>,
// aud = application account (TRUEOPEN), permissions = §5.13 CORTEX permission set plus JetStream, exp = issue time + ttl.
// issuer_account is written only when a signing key is used (public key != account public key) -- writing it when the account identity key self-signs makes validators reject it.
// iat is written by jwt/v2 itself in Encode from the real clock; it is not set here and no clock can be injected.
func (i *Issuer) UserJWT(userNkey string, decision Decision) (string, error) {
	claims := jwt.NewUserClaims(userNkey)
	if claims == nil {
		return "", errors.New("natsauth: user nkey is required to issue a user jwt")
	}
	claims.Name = "cortex:" + decision.OperatorAddress
	claims.Audience = i.cfg.CortexAccountPublicKey
	if i.cortexSigningPub != i.cfg.CortexAccountPublicKey {
		claims.IssuerAccount = i.cfg.CortexAccountPublicKey
	}
	claims.Permissions = CortexPermissions(i.cfg.JetStreamStream)
	claims.Expires = time.Now().Add(i.cfg.UserJWTTTL).Unix()
	return claims.Encode(i.cfg.CortexSigningKey)
}

// Response generates the authorization response: jwt on success, "<Code>: <detail>" on failure.
// If rejection is not a RejectError (an implementation defect) it is written as BINDING_MALFORMED -- the closed set of codes cannot be bypassed,
// and the raw text is left to the caller for logging only.
func (i *Issuer) Response(userNkey, serverID, userJWT string, rejection error) (string, error) {
	claims := jwt.NewAuthorizationResponseClaims(userNkey)
	if claims == nil {
		return "", errors.New("natsauth: user nkey is required to issue an authorization response")
	}
	claims.Audience = serverID
	if rejection != nil {
		var rej *RejectError
		if errors.As(rejection, &rej) {
			claims.Error = rej.Error()
		} else {
			claims.Error = string(CodeBindingMalformed) + ": " + genericFailureDetail
		}
	} else {
		claims.Jwt = userJWT
	}
	return claims.Encode(i.cfg.AuthSigningKey)
}
