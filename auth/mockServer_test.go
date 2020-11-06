package auth

import (
	jwtgo "github.com/dgrijalva/jwt-go/v4"
	"testing"
)

func TestMockServer_SignTokenWithAdditionalClaims(t *testing.T) {
	oidcMockServer, _ := NewOIDCMockServer()
	defer oidcMockServer.Server.Close()

	tests := []struct {
		name             string
		claims           OIDCClaims
		additionalClaims map[string]interface{}
		wantErr          bool
	}{
		{
			name:   "additional claim",
			claims: oidcMockServer.DefaultClaims(),
			additionalClaims: map[string]interface{}{
				"ias-admin": "true",
			},
			wantErr: false,
		}, {
			name:   "standard oidc claim in additional claim",
			claims: oidcMockServer.DefaultClaims(),
			additionalClaims: map[string]interface{}{
				"user_uuid": "fake",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedToken, err := oidcMockServer.SignTokenWithAdditionalClaims(tt.claims, tt.additionalClaims, oidcMockServer.DefaultHeaders())
			if (err != nil) != tt.wantErr {
				t.Errorf("SignTokenWithAdditionalClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				token, _, err := new(jwtgo.Parser).ParseUnverified(signedToken, jwtgo.MapClaims{})
				if err != nil {
					t.Errorf("SignTokenWithAdditionalClaims() error = %v, wantErr %v", err, tt.wantErr)
				}
				claims := token.Claims.(jwtgo.MapClaims)
				for k, v := range tt.additionalClaims {
					if value, exists := claims[k]; !exists || v != value {
						t.Errorf("additional claim %s missing in token or has wrong value %v vs %v ", k, v, value)
					}
				}
			}
		})
	}
}
