// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"reflect"
	"testing"
)

func TestOIDCClaims_getClaimAsString(t *testing.T) {
	tests := []struct {
		name      string
		mapClaims map[string]interface{}
		claimArg  string
		want      string
		wantErr   bool
	}{
		{
			name: "single string",
			mapClaims: map[string]interface{}{
				"testClaim": "testValue",
			},
			claimArg: "testClaim",
			want:     "testValue",
			wantErr:  false,
		}, {
			name: "single int",
			mapClaims: map[string]interface{}{
				"testClaim": 1,
			},
			claimArg: "testClaim",
			want:     "",
			wantErr:  true,
		}, {
			name: "string slice",
			mapClaims: map[string]interface{}{
				"testClaim": []string{"oneString", "anotherOne"},
			},
			claimArg: "testClaim",
			want:     "",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c := OIDCClaims{
				mapClaims: tt.mapClaims,
			}
			got, err := c.GetClaimAsString(tt.claimArg)
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
		name      string
		mapClaims map[string]interface{}
		claimArg  string
		want      []string
		wantErr   bool
	}{
		{
			name: "string slice",
			mapClaims: map[string]interface{}{
				"testClaim": []string{"oneString", "anotherOne"},
			},
			claimArg: "testClaim",
			want:     []string{"oneString", "anotherOne"},
			wantErr:  false,
		}, {
			name: "single string",
			mapClaims: map[string]interface{}{
				"testClaim": "myValue",
			},
			claimArg: "testClaim",
			want:     nil,
			wantErr:  true,
		}, {
			name: "single int",
			mapClaims: map[string]interface{}{
				"testClaim": 1,
			},
			claimArg: "testClaim",
			want:     nil,
			wantErr:  true,
		}, {
			name: "int slice",
			mapClaims: map[string]interface{}{
				"testClaim": []int{1, 2, 3},
			},
			claimArg: "testClaim",
			want:     nil,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c := OIDCClaims{
				mapClaims: tt.mapClaims,
			}
			got, err := c.GetClaimAsStringSlice(tt.claimArg)
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

func TestOIDCClaims_getAllClaims(t *testing.T) {
	mapClaims := map[string]interface{}{
		"testClaimSlice":  []string{"oneString", "anotherOne"},
		"testClaimString": "oneString",
		"number":          123,
		"boolean":         true,
	}

	c := OIDCClaims{
		mapClaims: mapClaims,
	}

	got := c.GetAllCustomClaims()
	if !reflect.DeepEqual(got, mapClaims) {
		t.Errorf("GetAllCustomClaims() got = %v, want %v", got, mapClaims)
	}
}
