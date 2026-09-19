package nodecontract

import (
	"crypto/sha256"
	"fmt"
)

const DomainTaskIDV1 = "TRUEOPEN_TASK_ID_V1"

// DeriveTaskIDFromRawSession is the sole adapter from the raw Hash32 carried by
// TaskOrderV2 to the frozen typed task-id preimage.
func DeriveTaskIDFromRawSession(sessionID []byte, orderSequence uint64) ([sha256.Size]byte, error) {
	if len(sessionID) != sha256.Size {
		return [sha256.Size]byte{}, fmt.Errorf("session_id must be Hash32")
	}
	return CanonicalHashBytes(DomainTaskIDV1, sessionID, Uint64BE(orderSequence)), nil
}
