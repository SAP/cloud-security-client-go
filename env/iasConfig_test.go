// SPDX-FileCopyrightText: 2020-2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
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

var testConfig = &Identity{
	ClientID:     "cef76757-de57-480f-be92-1d8c1c7abf16",
	ClientSecret: "[the_CLIENT.secret:3[/abc",
	Domains:      []string{"accounts400.ondemand.com", "my.arbitrary.domain"},
	URL:          "https://mytenant.accounts400.ondemand.com",
	ZoneUUID:     uuid.MustParse("bef12345-de57-480f-be92-1d8c1c7abf16"),
}

func TestGetIASConfig(t *testing.T) {
	tests := []struct {
		name          string
		k8sSecretPath string
		env           string
		want          *Identity
		wantErr       bool
	}{
		{
			name:    "[CF] single identity service instance bound",
			env:     "{\"identity\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"[the_CLIENT.secret:3[/abc\",\"domains\":[\"accounts400.ondemand.com\",\"my.arbitrary.domain\"],\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\",\"zone_uuid\":\"bef12345-de57-480f-be92-1d8c1c7abf16\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]}]}",
			want:    testConfig,
			wantErr: false,
		},
		{
			name:    "[CF] multiple identity service bindings",
			env:     "{\"identity\":[{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"[the_CLIENT.secret:3[/abc\",\"domains\":[\"accounts400.ondemand.com\",\"my.arbitrary.domain\"],\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]},{\"binding_name\":null,\"credentials\":{\"clientid\":\"cef76757-de57-480f-be92-1d8c1c7abf16\",\"clientsecret\":\"the_CLIENT.secret:3[/abc\",\"domain\":\"accounts400.ondemand.com\",\"token_url\":\"https://mytenant.accounts400.ondemand.com/oauth2/token\",\"url\":\"https://mytenant.accounts400.ondemand.com\"},\"instance_name\":\"my-ams-instance\",\"label\":\"identity\",\"name\":\"my-ams-instance\",\"plan\":\"application\",\"provider\":null,\"syslog_drain_url\":null,\"tags\":[\"ias\"],\"volume_mounts\":[]}]}",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "[CF] no identity service binding",
			env:     "{}",
			want:    nil,
			wantErr: true,
		},
		{
			name:          "[K8s] single identity service instance bound",
			k8sSecretPath: path.Join("testdata", "k8s", "identity"),
			want:          testConfig,
			wantErr:       false,
		},
		{
			name:          "[K8s] no bindings on default secret path",
			k8sSecretPath: "ignore",
			want:          nil,
			wantErr:       true,
		},
		{
			name:          "[K8s] multiple identity service bindings",
			k8sSecretPath: path.Join("testdata", "k8s", "multi-instances"),
			want:          nil,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.env != "" {
				err = setTestEnv(tt.env)
			} else if tt.k8sSecretPath != "" {
				err = setK8sTestEnv(tt.k8sSecretPath)
			}
			if err != nil {
				t.Error(err)
			}
			got, err := GetIASConfig()
			if err != nil {
				if !tt.wantErr {
					t.Errorf("GetIASConfig() error = %v, wantErr:%v", err, tt.wantErr)
					return
				}
				t.Logf("GetIASConfig() error = %v, wantErr:%v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIASConfig() got = %v, want %v", got, tt.want)
			}
			err = clearTestEnv()
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func setTestEnv(vcapServices string) error {
	err := os.Setenv("VCAP_SERVICES", vcapServices)
	if err != nil {
		return fmt.Errorf("error preparing test: could not set env VCAP_SERVICES: %w", err)
	}
	err = os.Setenv("VCAP_APPLICATION", "{}")
	if err != nil {
		return fmt.Errorf("error preparing test: could not set env VCAP_APPLICATION: %w", err)
	}
	return nil
}

func setK8sTestEnv(secretPath string) error {
	err := os.Setenv("KUBERNETES_SERVICE_HOST", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("error preparing test: could not set env KUBERNETES_SERVICE_HOST: %w", err)
	}
	if secretPath != "" && secretPath != "ignore" {
		err = os.Setenv("IAS_CONFIG_PATH", secretPath)
		if err != nil {
			return fmt.Errorf("error preparing test: could not set env IAS_CONFIG_PATH: %w", err)
		}
	}
	return nil
}

func clearTestEnv() error {
	err := os.Unsetenv("VCAP_SERVICES")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env VCAP_SERVICES: %w", err)
	}
	err = os.Unsetenv("VCAP_APPLICATION")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env VCAP_APPLICATION/VCAP_SERVICES: %w", err)
	}
	err = os.Unsetenv("KUBERNETES_SERVICE_HOST")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env KUBERNETES_SERVICE_HOST: %w", err)
	}
	err = os.Unsetenv("IAS_CONFIG_PATH")
	if err != nil {
		return fmt.Errorf("error cleaning up after test: could not unset env IAS_CONFIG_PATH: %w", err)
	}
	return nil
}
