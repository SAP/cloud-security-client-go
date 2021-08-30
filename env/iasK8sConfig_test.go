// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"fmt"
	"github.com/google/uuid"
	"os"
	"path"
	"reflect"
	"testing"
)

var (
	testK8sConfig *Identity = &Identity{
		ClientID:     "cef76757-de57-480f-be92-1d8c1c7abf16",
		ClientSecret: "[the_CLIENT.secret:3[/abc",
		Domains:      []string{"accounts400.ondemand.com", "my.arbitrary.domain"},
		URL:          "https://mytenant.accounts400.ondemand.com",
		ZoneUUID:     uuid.MustParse("bef12345-de57-480f-be92-1d8c1c7abf16"),
	}
)

func TestGetIASConfigFromK8s(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    *Identity
		wantErr bool
	}{
		{
			name:    "single ias service instance bound",
			path:    path.Join("testdata", "k8s", "identity"),
			want:    testK8sConfig,
			wantErr: false,
		},
		{
			name:    "no bindings on default path",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "multiple bindings",
			path:    path.Join("testdata", "k8s", "multi-instances"),
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setK8sTestEnv(tt.path)
			if err != nil {
				t.Error(err)
			}
			got, err := GetIASConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetIASConfigInUserProvidedService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIASConfigInUserProvidedService() got = %v, want %v", got, tt.want)
			}
			err = clearK8sTestEnv()
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func setK8sTestEnv(path string) error {
	err := os.Setenv("KUBERNETES_SERVICE_HOST", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("error preparing test: could not set env KUBERNETES_SERVICE_HOST: %w", err)
	}
	if path != "" {
		err = os.Setenv("IAS_CONFIG_PATH", path)
		if err != nil {
			return fmt.Errorf("error preparing test: could not set env IAS_CONFIG_PATH: %w", err)
		}
	}
	return nil
}

func clearK8sTestEnv() error {
	err := os.Unsetenv("KUBERNETES_SERVICE_HOST")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env KUBERNETES_SERVICE_HOST: %w", err)
	}
	err = os.Unsetenv("IAS_CONFIG_PATH")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env IAS_CONFIG_PATH: %w", err)
	}
	return nil
}
