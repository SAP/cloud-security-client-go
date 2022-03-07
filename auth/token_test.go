// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
)

func TestToken_getClaimAsString(t *testing.T) {
	tests := []struct {
		name       string
		claimValue interface{}
		claimArg   string
		want       string
		wantErr    bool
	}{
		{
			name:       "single string",
			claimValue: "testValue",
			claimArg:   "testClaim",
			want:       "testValue",
			wantErr:    false,
		}, {
			name:       "single int",
			claimValue: 1,
			claimArg:   "testClaim",
			want:       "",
			wantErr:    true,
		}, {
			name:       "string slice",
			claimValue: []string{"oneString", "anotherOne"},
			claimArg:   "testClaim",
			want:       "",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			err := token.Set(tt.claimArg, tt.claimValue)
			if err != nil {
				t.Errorf("Error preparing test: %v", err)
			}
			stdToken := IdToken{
				jwtToken: token,
			}
			got, err := stdToken.GetClaimAsString(tt.claimArg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClaimAsString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetClaimAsString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDCClaims_getClaimAsStringSlice(t *testing.T) {
	tests := []struct {
		name       string
		claimValue interface{}
		claimArg   string
		want       []string
		wantErr    bool
	}{
		{
			name:       "string slice",
			claimValue: []string{"oneString", "anotherOne"},
			claimArg:   "testClaim",
			want:       []string{"oneString", "anotherOne"},
			wantErr:    false,
		}, {
			name:       "single string",
			claimValue: "myValue",
			claimArg:   "testClaim",
			want:       nil,
			wantErr:    true,
		}, {
			name:       "single int",
			claimValue: 1,
			claimArg:   "testClaim",
			want:       nil,
			wantErr:    true,
		}, {
			name:       "int slice",
			claimValue: []int{1, 2, 3},
			claimArg:   "testClaim",
			want:       nil,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			err := token.Set(tt.claimArg, tt.claimValue)
			if err != nil {
				t.Errorf("Error preparing test: %v", err)
			}
			stdToken := IdToken{
				jwtToken: token,
			}
			got, err := stdToken.GetClaimAsStringSlice(tt.claimArg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClaimAsStringSlice() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetClaimAsStringSlice() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDCClaims_getAllClaimsAsMap(t *testing.T) {
	token, err := NewToken("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3RLZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiY2xpZW50aWQiXSwiZW1haWwiOiJmb29AYmFyLm9yZyIsImV4cCI6MTYyMDA5MjI1MSwiZmFtaWx5X25hbWUiOiJCYXIiLCJnaXZlbl9uYW1lIjoiRm9vIiwiaWFzLWFkbWluIjoidHJ1ZSIsImlhdCI6MTYxOTc5MjI1MSwiaXNzIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NTQ0ODIiLCJqdGkiOiI4NjI3NGE1Ny01N2FlLTQ5NDktOWRjOC03ODY0NjcyOWYzYmMiLCJuYmYiOjE2MTk3OTIyNTEsInVzZXJfdXVpZCI6IjIyMjIyMjIyLTMzMzMtNDQ0NC01NTU1LTY2NjY2NjY2NjY2NiIsInpvbmVfdXVpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTg4ODg4ODg4ODg4OCJ9.W-Owtad1oybqDI3tsJYGIIZPXBz2IdKOFoMCp07mv8kBNNVWNL0FbRIwilqU-cry_m-DA__5dKaVwaNW7q_6nCmIdvfmqdDJGCd6836AU4VC18uylSKMwVrm7o3TZsS04dDCjR5pnrSR2tzr-3VrMECRK7YSW4tuAaQC8XDWEnVIxz_l7eIB3v09SeRXi3iiqiYTUTyP3o5EU2Ae1tjYSfgLvOmkHTV406Rp5oaiZZV-jdMq7w-JaD-9JLon8O3XRdTApiYJ6yI9sXLcBrElHzy8M2HKm4FvOb66cJYT4GtB8Ntoq7XQKor0oW5dPPXuEBIl77Hz6PgNa7WYKkBi_w")
	if err != nil {
		t.Errorf("Error while preparing test: %v", err)
	}

	got := token.GetAllClaimsAsMap()
	if len(got) != 12 {
		t.Errorf("GetAllClaimsAsMap() number of attributes got = %v, want %v", len(got), 12)
	}
}

func TestOIDCClaims_getClaimAsMap(t *testing.T) {
	token, err := NewToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbmYiOnsieDV0I1MyNTYiOiIwX3daeG5EUXd6dkxqLWh0NHNZbFQ3RzBIMURuT2ZPUC02MGFxeU1PVDI4IiwicHJvb2Z0b2tlbiI6InRydWUifX0.3Xi2fe-m-6lc1Ze9_AsnNpkYAG-LKFPHCld5EggQTW4")
	if err != nil {
		t.Errorf("Error while preparing test: %v", err)
	}

	got, err := token.GetClaimAsMap(claimCnf)
	if err != nil {
		t.Errorf("GetClaimAsStringSlice() error = %v", err)
		return
	}
	if len(got) != 2 {
		t.Errorf("GetClaimAsMap() number of members got = %v, want %v", len(got), 2)
	}
	cnfClaimMemberX5t := token.getCnfClaimMember(claimCnfMemberX5t)
	if cnfClaimMemberX5t != "0_wZxnDQwzvLj-ht4sYlT7G0H1DnOfOP-60aqyMOT28" {
		t.Errorf("getCnfClaimMember()[%v] got = %v", claimCnfMemberX5t, cnfClaimMemberX5t)
	}
}

func TestOIDCClaims_getSAPIssuer(t *testing.T) {
	tests := []struct {
		name          string
		iss           string
		iasIss        string
		WantCustomIss string
		wantIss       string
	}{
		{
			name:          "iss claim only",
			iss:           "http://localhost:3030",
			wantIss:       "http://localhost:3030",
			WantCustomIss: "",
		},
		{
			name:          "iss and ias_iss claim",
			iss:           "http://localhost:3030",
			iasIss:        "https://custom.oidc-server.com",
			wantIss:       "https://custom.oidc-server.com",
			WantCustomIss: "http://localhost:3030",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			token, err := NewToken("eyJhbGciOiJIUzI1NiJ9.e30.ZRrHA1JJJW8opsbCGfG_HACGpVUMN_a9IV7pAx_Zmeo")
			jwtToken := token.getJwtToken()
			_ = jwtToken.Set("iss", tt.iss)
			if tt.iasIss != "" {
				_ = jwtToken.Set("ias_iss", tt.iasIss)
			}
			if err != nil {
				t.Errorf("Error while preparing test: %v", err)
			}
			issuerActual := token.CustomIssuer()
			if issuerActual != tt.WantCustomIss {
				t.Errorf("CustomIssuer() got = %v, want %v", issuerActual, tt.WantCustomIss)
			}
			iasIssuerActual := token.Issuer()
			if iasIssuerActual != tt.wantIss {
				t.Errorf("Issuer() got = %v, want %v", iasIssuerActual, tt.wantIss)
			}
		})
	}
}
