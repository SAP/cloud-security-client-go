package core

type authResult interface {
	Success() bool
	Error() error
	Details() interface{}
}

type AuthResult struct {
	success bool
	error   error
	details *OIDCClaims
}

func (r AuthResult) Success() bool {
	return r.success
}

func (r AuthResult) Error() error {
	return r.error
}

func (r AuthResult) Details() interface{} {
	return r.details
}
