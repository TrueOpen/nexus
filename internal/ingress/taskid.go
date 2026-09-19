package ingress

import (
	"encoding/hex"

	"github.com/TrueOpen/nexus/internal/nodecontract"
)

func deriveTaskID(sessionID string, orderSequence uint64) (string, error) {
	rawSessionID, err := nodecontract.Hash32Bytes("session_id", sessionID)
	if err != nil {
		return "", err
	}
	taskID, err := nodecontract.DeriveTaskIDFromRawSession(rawSessionID, orderSequence)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(taskID[:]), nil
}
