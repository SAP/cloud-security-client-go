// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"github.com/sap/cloud-security-client-go/mocks"
	"testing"
)

func TestMockServer_SignTokenWithAdditionalClaims(t *testing.T) {
	oidcMockServer, _ := mocks.NewOIDCMockServer()
	defer oidcMockServer.Server.Close()

	tests := []struct {
		name             string
		claims           mocks.OIDCClaims
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
				token, err := newToken(signedToken)
				if err != nil {
					t.Errorf("SignTokenWithAdditionalClaims() error = %v, wantErr %v", err, tt.wantErr)
				}
				for k, v := range tt.additionalClaims {
					if value, err := token.GetClaimAsString(k); err != nil || v != value {
						t.Errorf("additional claim %s missing in token or has wrong value %v vs %v ", k, v, value)
					}
				}
			}
		})
	}
}
