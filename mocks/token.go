package mocks

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"

	"github.com/sap/cloud-security-client-go/auth"
)

type Token struct {
	JwtToken jwt.Token
}

// NewToken creates a Token from an encoded jwt. !!! WARNING !!! No validation done when creating a Token this way. Use only in tests!
func NewToken(encodedToken string) (Token, error) {
	decodedToken, err := jwt.ParseString(encodedToken, jwt.WithToken(openid.New()))
	if err != nil {
		return Token{}, err
	}

	return Token{
		JwtToken: decodedToken, // encapsulates jwt.token_gen from github.com/lestrrat-go/jwx/jwt
	}, nil
}

// NewTokenFromClaims creates a Token from claims. !!! WARNING !!! No validation done when creating a Token this way. Use only in tests!
func NewTokenFromClaims(claims map[string]interface{}) (Token, error) {
	jwtToken := jwt.New()
	for key, value := range claims {
		err := jwtToken.Set(key, value)
		if err != nil {
			return Token{}, err
		}
	}

	return Token{
		JwtToken: jwtToken,
	}, nil
}

// TokenValue returns encoded token string
func (t Token) TokenValue() string {
	block, _ := pem.Decode([]byte(dummyKey))
	if block == nil {
		panic("failed to parse PEM block containing dummyKey")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("unable to create mock server: error generating rsa key: %v", err))
	}

	signedJwt, err := jwt.Sign(t.JwtToken, jwa.RS256, rsaKey)
	if err != nil {
		panic(err)
	}

	return string(signedJwt)
}

func (t Token) Audience() []string {
	return t.JwtToken.Audience()
}

func (t Token) Expiration() time.Time {
	return t.JwtToken.Expiration()
}

func (t Token) IsExpired() bool {
	return t.Expiration().Add(1 * time.Minute).Before(time.Now())
}

func (t Token) IssuedAt() time.Time {
	return t.JwtToken.IssuedAt()
}

func (t Token) CustomIssuer() string {
	// only return iss if ias_iss does exist
	if !t.HasClaim(auth.ClaimIasIssuer) {
		return ""
	}
	return t.JwtToken.Issuer()
}

func (t Token) Issuer() string {
	// return standard issuer if ias_iss is not set
	v, err := t.GetClaimAsString(auth.ClaimIasIssuer)
	if errors.Is(err, ErrClaimNotExists) {
		return t.JwtToken.Issuer()
	}
	return v
}

func (t Token) NotBefore() time.Time {
	return t.JwtToken.NotBefore()
}

func (t Token) Subject() string {
	return t.JwtToken.Subject()
}

func (t Token) GivenName() string {
	v, _ := t.GetClaimAsString(auth.ClaimGivenName)
	return v
}

func (t Token) FamilyName() string {
	v, _ := t.GetClaimAsString(auth.ClaimFamilyName)
	return v
}

func (t Token) Email() string {
	v, _ := t.GetClaimAsString(auth.ClaimEmail)
	return v
}

func (t Token) ZoneID() string {
	v, _ := t.GetClaimAsString(auth.ClaimSapGlobalZoneID)
	return v
}

func (t Token) UserUUID() string {
	v, _ := t.GetClaimAsString(auth.ClaimSapGlobalUserID)
	return v
}

// ErrClaimNotExists shows that the requested custom claim does not exist in the token
var ErrClaimNotExists = errors.New("claim does not exist in the token")

func (t Token) HasClaim(claim string) bool {
	_, exists := t.JwtToken.Get(claim)
	return exists
}

func (t Token) GetClaimAsString(claim string) (string, error) {
	value, exists := t.JwtToken.Get(claim)
	if !exists {
		return "", ErrClaimNotExists
	}
	stringValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("unable to assert claim %s type as string. Actual type: %T", claim, value)
	}
	return stringValue, nil
}

func (t Token) GetClaimAsStringSlice(claim string) ([]string, error) {
	value, exists := t.JwtToken.Get(claim)
	if !exists {
		return nil, ErrClaimNotExists
	}
	res, ok := value.([]string)
	if !ok {
		return nil, fmt.Errorf("unable to assert type of claim %s to string. Actual type: %T", claim, value)
	}
	return res, nil
}

func (t Token) GetAllClaimsAsMap() map[string]interface{} {
	mapClaims, _ := t.JwtToken.AsMap(context.TODO()) // err can not really occur on jwt.Token
	return mapClaims
}

func (t Token) GetClaimAsMap(claim string) (map[string]interface{}, error) {
	value, exists := t.JwtToken.Get(claim)
	if !exists {
		return nil, ErrClaimNotExists
	}
	res, ok := value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unable to assert type of claim %s to map[string]interface{}. Actual type: %T", claim, value)
	}
	return res, nil
}

func (t Token) getJwtToken() jwt.Token {
	return t.JwtToken
}

func (t Token) getCnfClaimMember(memberName string) string {
	cnfClaim, err := t.GetClaimAsMap(auth.ClaimCnf)
	if errors.Is(err, ErrClaimNotExists) || cnfClaim == nil {
		return ""
	}
	res, ok := cnfClaim[memberName]
	if ok {
		return res.(string)
	}
	return ""
}
