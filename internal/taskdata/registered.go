package taskdata

import (
	"context"
	"errors"
	"fmt"

	"github.com/TrueOpen/nexus/internal/registeredkey"
)

// verifyRegisteredTaskDataKey is the registered-key branch of a USER request without a grant whose
// signature recovers to an address other than requester_address. The session is the one of this
// Builder's local record of the Task, never one the request names on its own: no local record is
// DATA_ACCESS_INVALID_SIGNATURE. Then, in order: the session is not CLOSED, is owned by
// requester_address and has recovered as its current key, else DATA_ACCESS_INVALID_SIGNATURE;
// current_height <= the key's expiry, else DATA_ACCESS_SESSION_GRANT_EXPIRED; the request is
// metadata or fetch of an OUTPUT object, else DATA_ACCESS_SESSION_METHOD_NOT_ALLOWED.
func verifyRegisteredTaskDataKey(ctx context.Context, auth RequestAuthV1, env SessionGrantEnv, recovered [20]byte) error {
	if env.SessionKeys == nil || env.LocalTask == nil {
		return fmt.Errorf("%w: USER signature does not recover to requester_address", ErrInvalidSignature)
	}
	found, err := env.LocalTask(ctx, auth.Key.SessionID, auth.Key.TaskID)
	if err != nil {
		return fmt.Errorf("%w: local task record", ErrAuthorityUnavailable)
	}
	if !found {
		return fmt.Errorf("%w: no local task record for a registered-key request", ErrInvalidSignature)
	}
	if env.Chain == nil {
		return fmt.Errorf("%w: no chain to read the current height from", ErrAuthorityUnavailable)
	}
	height, err := env.Chain.CurrentHeight(ctx)
	if err != nil || height == 0 {
		return fmt.Errorf("%w: current height", ErrAuthorityUnavailable)
	}
	state, err := env.SessionKeys.Lookup(ctx, auth.Key.SessionID, height)
	if err != nil {
		return fmt.Errorf("%w: session state", ErrAuthorityUnavailable)
	}
	switch err := registeredkey.CheckRequest(state, auth.RequesterAddress, recovered, height); {
	case errors.Is(err, registeredkey.ErrKeyExpired):
		return fmt.Errorf("%w: the session's registered key has expired", ErrSessionGrantExpired)
	case err != nil:
		return fmt.Errorf("%w: USER signature recovers to neither requester_address nor the session's registered key", ErrInvalidSignature)
	}
	if !sessionAllowed(auth) {
		return fmt.Errorf("%w: only metadata and fetch of an OUTPUT object may be signed by a session key", ErrSessionMethodNotAllowed)
	}
	return nil
}
