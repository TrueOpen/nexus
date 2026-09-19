package outputdelivery

import "errors"

var (
	ErrPlaintextRequired = errors.New("OUTPUT_PLAINTEXT_REQUIRED")
	ErrInvalidUTF8       = errors.New("OUTPUT_INVALID_UTF8")
	ErrTooLarge          = errors.New("OUTPUT_TOO_LARGE")
	ErrHashMismatch      = errors.New("OUTPUT_HASH_MISMATCH")
	ErrConflict          = errors.New("OUTPUT_CONFLICT")
	ErrUnauthorized      = errors.New("OUTPUT_UNAUTHORIZED")
	ErrExpired           = errors.New("OUTPUT_EXPIRED")
	ErrAlreadyAcked      = errors.New("OUTPUT_ALREADY_ACKED")
	ErrUnavailable       = errors.New("OUTPUT_UNAVAILABLE")
	ErrDeliveryFailure   = errors.New("OUTPUT_DELIVERY_UNAVAILABLE")
)
