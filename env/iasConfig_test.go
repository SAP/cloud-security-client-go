// SPDX-FileCopyrightText: 2020-2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"path"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testConfig = &DefaultIdentity{
	ClientID:                "cef76757-de57-480f-be92-1d8c1c7abf16",
	ClientSecret:            "[the_CLIENT.secret:3[/abc",
	Domains:                 []string{"accounts400.ondemand.com", "my.arbitrary.domain"},
	URL:                     "https://mytenant.accounts400.ondemand.com",
	AppTID:                  "70cd0de3-528a-4655-b56a-5862591def5c",
	AuthorizationInstanceID: "8d5423d7-bda4-461c-9670-1b9adc142f0a",
	AuthorizationBundleURL:  "https://mytenant.accounts400.ondemand.com/sap/ams/v1/bundles",
}

func TestParseIdentityConfig(t *testing.T) {
	tests := []struct {
		name          string
		k8sSecretPath string
		env           string
		want          Identity
		wantErr       bool
	}{
		{
			name:    "[CF] single identity service instance bound",
			env:     `{"identity":[{"binding_name":null,"credentials":{"clientid":"cef76757-de57-480f-be92-1d8c1c7abf16","clientsecret":"[the_CLIENT.secret:3[/abc","domains":["accounts400.ondemand.com","my.arbitrary.domain"],"token_url":"https://mytenant.accounts400.ondemand.com/oauth2/token","url":"https://mytenant.accounts400.ondemand.com", "app_tid":"70cd0de3-528a-4655-b56a-5862591def5c", "authorization_instance_id":"8d5423d7-bda4-461c-9670-1b9adc142f0a", "authorization_bundle_url":"https://mytenant.accounts400.ondemand.com/sap/ams/v1/bundles"},"instance_name":"my-ams-instance","label":"identity","name":"my-ams-instance","plan":"application","provider":null,"syslog_drain_url":null,"tags":["ias"],"volume_mounts":[]}]}`,
			want:    testConfig,
			wantErr: false,
		},
		{
			name:    "[CF] multiple identity service bindings",
			env:     `{"identity":[{"binding_name":null,"credentials":{"clientid":"cef76757-de57-480f-be92-1d8c1c7abf16","clientsecret":"[the_CLIENT.secret:3[/abc","domains":["accounts400.ondemand.com","my.arbitrary.domain"],"token_url":"https://mytenant.accounts400.ondemand.com/oauth2/token","url":"https://mytenant.accounts400.ondemand.com"},"instance_name":"my-ams-instance","label":"identity","name":"my-ams-instance","plan":"application","provider":null,"syslog_drain_url":null,"tags":["ias"],"volume_mounts":[]},{"binding_name":null,"credentials":{"clientid":"cef76757-de57-480f-be92-1d8c1c7abf16","clientsecret":"the_CLIENT.secret:3[/abc","domain":"accounts400.ondemand.com","token_url":"https://mytenant.accounts400.ondemand.com/oauth2/token","url":"https://mytenant.accounts400.ondemand.com"},"instance_name":"my-ams-instance","label":"identity","name":"my-ams-instance","plan":"application","provider":null,"syslog_drain_url":null,"tags":["ias"],"volume_mounts":[]}]}`,
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
			k8sSecretPath: path.Join("testdata", "k8s", "single-instance"),
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
		{
			name:          "[K8s] single identity service instance bound with secretKey=credentials",
			k8sSecretPath: path.Join("testdata", "k8s", "single-instance-onecredentialsfile"),
			want:          testConfig,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.env != "" {
				setTestEnv(t, tt.env)
			} else if tt.k8sSecretPath != "" {
				setK8sTestEnv(t, tt.k8sSecretPath)
			}
			if err != nil {
				t.Error(err)
			}
			got, err := ParseIdentityConfig()
			if err != nil {
				if !tt.wantErr {
					t.Errorf("ParseIdentityConfig() error = %v, wantErr:%v", err, tt.wantErr)
					return
				}
				t.Logf("ParseIdentityConfig() error = %v, wantErr:%v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseIdentityConfig() got = %v, want %v", got, tt.want)
			}
			if tt.want != nil {
				assert.False(t, tt.want.IsCertificateBased())
			}
		})
	}
}

func TestX509BasedCredentials(t *testing.T) {
	setTestEnv(t, `{"identity":[{"credentials":{"clientid":"cef76757-de57-480f-be92-1d8c1c7abf16","certificate":"theCertificate","key":"thekey","app_tid":"70cd0de3-528a-4655-b56a-5862591def5c"}}]}`)
	got, err := ParseIdentityConfig()
	assert.NoError(t, err)
	assert.Equal(t, got.GetClientID(), "cef76757-de57-480f-be92-1d8c1c7abf16")
	assert.Equal(t, got.GetCertificate(), "theCertificate")
	assert.Equal(t, got.GetKey(), "thekey")
	assert.Equal(t, got.GetZoneUUID().String(), "70cd0de3-528a-4655-b56a-5862591def5c")
	assert.True(t, got.IsCertificateBased())
}

// Cleanup when go 1.18 is released
func setTestEnv(t *testing.T, vcapServices string) {
	t.Setenv("VCAP_SERVICES", vcapServices)
	t.Setenv("VCAP_APPLICATION", "{}")
}

func setK8sTestEnv(t *testing.T, secretPath string) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "0.0.0.0")
	if secretPath != "" && secretPath != "ignore" {
		t.Setenv("IAS_CONFIG_PATH", secretPath)
	}
}
