package token_client

import "github.com/dgrijalva/jwt-go"

func (tokenService TokenService) getTokenSigningKey(token *jwt.Token) (interface{}, error) {
	var subdomain = ""

	if claims, ok := token.Claims.(*JwtClaims); ok {
		subdomain = claims.ExtAttribute.Zdn
	}

	tokenUrl := "https://" + subdomain + "." + defaultXsuaaConfig.uaaDomain + "/token_keys"

	set, err := tokenService.Fetch(tokenUrl)
	if err != nil {
		return nil, err
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, jwt.NewValidationError("expecting JWT header to have string kid", jwt.ValidationErrorMalformed)
	}

	if key := set.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, jwt.NewValidationError("unable to find key", jwt.ValidationErrorUnverifiable)
}
