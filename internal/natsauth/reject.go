package natsauth

import "fmt"

// Code is the closed set of error codes from §5.14.3. The response error field is "<Code>: <detail>"; no new values may be added.
type Code string

const (
	CodeBindingMalformed        Code = "BINDING_MALFORMED"
	CodeChainIDMismatch         Code = "CHAIN_ID_MISMATCH"
	CodeNkeyMismatch            Code = "NKEY_MISMATCH"
	CodeNonceSignatureInvalid   Code = "NONCE_SIGNATURE_INVALID"
	CodeServiceKeyNotActive     Code = "SERVICE_KEY_NOT_ACTIVE"
	CodeServiceKeyNonceMismatch Code = "SERVICE_KEY_NONCE_MISMATCH"
	CodeBindingSignatureInvalid Code = "BINDING_SIGNATURE_INVALID"
	CodeCortexNotRegistered     Code = "CORTEX_NOT_REGISTERED"
	CodeChainUnavailable        Code = "CHAIN_UNAVAILABLE"
)

// AllCodes returns the closed set in §5.14.3 table order; tests use it to prevent drift.
func AllCodes() []Code {
	return []Code{CodeBindingMalformed, CodeChainIDMismatch, CodeNkeyMismatch, CodeNonceSignatureInvalid,
		CodeServiceKeyNotActive, CodeServiceKeyNonceMismatch, CodeBindingSignatureInvalid, CodeCortexNotRegistered, CodeChainUnavailable}
}

// RejectError is one rejection: Code goes into the response; Detail goes only into logs and the response text and carries nothing beyond fixed text.
// Cause goes only into logs and errors.Is/errors.As, never the response text, so raw chain-query errors do not leak to the caller.
type RejectError struct {
	Code   Code
	Detail string
	Cause  error
}

func (e *RejectError) Error() string { return string(e.Code) + ": " + e.Detail }

func (e *RejectError) Unwrap() error { return e.Cause }

// Reject constructs a rejection without an underlying cause.
func Reject(code Code, format string, args ...any) error {
	return &RejectError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// RejectWithCause constructs a rejection with an underlying cause attached: Detail is fixed text for the response,
// cause is used only for logs and errors.Is and is never concatenated into Detail.
func RejectWithCause(code Code, cause error, format string, args ...any) error {
	return &RejectError{Code: code, Detail: fmt.Sprintf(format, args...), Cause: cause}
}
