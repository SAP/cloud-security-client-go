package token_client

type jwk struct {
	kty string
	e   string
	n   string
	use string
	kid string
	alg string
}

const (
	ValidationErrorMalformed        int32 = 1 << iota // Token is malformed
	ValidationErrorUnverifiable                       // Token could not be verified because of signing problems
	ValidationErrorSignatureInvalid                   // Signature validation failed

	// Standard Claim validation errors
	ValidationErrorAudience      // AUD validation failed
	ValidationErrorExpired       // EXP validation failed
	ValidationErrorIssuedAt      // IAT validation failed
	ValidationErrorIssuer        // ISS validation failed
	ValidationErrorNotValidYet   // NBF validation failed
	ValidationErrorId            // JTI validation failed
	ValidationErrorClaimsInvalid // Generic claims validation error
)

// Helper for constructing a ValidationError with a string error message
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText,
		Errors: errorFlags,
	}
}

// The error from Parse if token is not valid
type ValidationError struct {
	Inner  error  // stores the error returned by external dependencies, i.e.: KeyFunc
	Errors uint32 // bitfield.  see ValidationError... constants
	text   string // errors that do not have a valid error just have text
}

// Validation error is an error type
func (e ValidationError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

// No errors
func (e *ValidationError) valid() bool {
	return e.Errors == 0
}
