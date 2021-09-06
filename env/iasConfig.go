// SPDX-FileCopyrightText: 2020-2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	yaml "gopkg.in/yaml.v3"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
)

const iasServiceName = "identity"
const iasSecretKeyDefault = "credentials"
const vcapServicesEnvKey = "VCAP_SERVICES"
const iasConfigPathKey = "IAS_CONFIG_PATH"
const iasConfigPathDefault = "/etc/secrets/sapbtp/identity"

// VCAPServices is the Cloud Foundry environment variable that stores information about services bound to the application
type VCAPServices struct {
	Identity []struct {
		Credentials Identity `json:"credentials"`
	} `json:"identity"`
}

// Identity represents the parsed credentials from the ias binding
type Identity struct {
	ClientID             string    `json:"clientid"`
	ClientSecret         string    `json:"clientsecret"`
	Domains              []string  `json:"domains"`
	URL                  string    `json:"url"`
	ZoneUUID             uuid.UUID `json:"zone_uuid"`
	ProofTokenURL        string    `json:"prooftoken_url"`
	OsbURL               string    `json:"osb_url"`
	Certificate          string    `json:"certificate"`
	Key                  string    `json:"key"`
	CertificateExpiresAt string    `json:"certificate_expires_at"`
}

// GetIASConfig parses the IAS config from the applications environment
func GetIASConfig() (*Identity, error) {
	switch getPlatform() { //nolint:exhaustive // Unknown case is handled by default
	case cloudFoundry:
		var vcapServices VCAPServices
		vcapServicesString := os.Getenv(vcapServicesEnvKey)
		err := json.Unmarshal([]byte(vcapServicesString), &vcapServices)
		if err != nil {
			return nil, fmt.Errorf("cannot parse vcap services: %w", err)
		}
		if len(vcapServices.Identity) == 0 {
			return nil, fmt.Errorf("no '%s' service instance bound to the application", iasServiceName)
		}
		if len(vcapServices.Identity) > 1 {
			return nil, fmt.Errorf("more than one '%s' service instance bound to the application. This is currently not supported", iasServiceName)
		}
		return &vcapServices.Identity[0].Credentials, nil
	case kubernetes:
		var secretPath = os.Getenv(iasConfigPathKey)
		if secretPath == "" {
			secretPath = iasConfigPathDefault
		}
		identities, err := readServiceBindings(secretPath)
		if err != nil || len(identities) == 0 {
			return nil, fmt.Errorf("cannot find '%s' service binding from secret path '%s'", iasServiceName, secretPath)
		} else if len(identities) > 1 {
			return nil, fmt.Errorf("found more than one '%s' service instance from secret path '%s'. This is currently not supported", iasServiceName, secretPath)
		}
		return &identities[0], nil
	default:
		return nil, fmt.Errorf("unable to parse '%s' service config: unknown environment detected", iasServiceName)
	}
}

func readServiceBindings(secretPath string) ([]Identity, error) {
	instancesBound, err := ioutil.ReadDir(secretPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read service directory '%s' for identity service: %w", secretPath, err)
	}
	identities := []Identity{}
	for _, instanceBound := range instancesBound {
		if !instanceBound.IsDir() {
			continue
		}
		serviceInstancePath := path.Join(secretPath, instanceBound.Name())
		instanceSecretFiles, err := ioutil.ReadDir(serviceInstancePath)
		if err != nil {
			return nil, fmt.Errorf("cannot read service instance directory '%s' for '%s' service instance '%s': %w", serviceInstancePath, iasServiceName, instanceBound.Name(), err)
		}
		instanceSecretsJSON, err := readCredentialsFileToJSON(serviceInstancePath, instanceSecretFiles)
		if instanceSecretsJSON == nil || err != nil {
			instanceSecretsJSON, err = readSecretFilesToJSON(serviceInstancePath, instanceSecretFiles)
			if err != nil {
				return nil, err
			}
		}
		identity := Identity{}
		if err := json.Unmarshal(instanceSecretsJSON, &identity); err != nil {
			return nil, fmt.Errorf("cannot unmarshal json content in directory '%s' for '%s' service instance: %w", serviceInstancePath, iasServiceName, err)
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

func readCredentialsFileToJSON(serviceInstancePath string, instanceSecretFiles []fs.FileInfo) ([]byte, error) {
	for _, instanceSecretFile := range instanceSecretFiles {
		if !instanceSecretFile.IsDir() && instanceSecretFile.Name() == iasSecretKeyDefault {
			serviceInstanceCredentialsPath := path.Join(serviceInstancePath, instanceSecretFile.Name())
			credentials, err := ioutil.ReadFile(serviceInstanceCredentialsPath)
			if err != nil {
				return nil, fmt.Errorf("cannot read content from '%s': %w", serviceInstanceCredentialsPath, err)
			}
			if json.Valid(credentials) {
				return credentials, nil
			}
		}
	}
	return nil, nil
}

func readSecretFilesToJSON(serviceInstancePath string, instanceSecretFiles []fs.FileInfo) ([]byte, error) {
	instanceCredentialsMap := make(map[string]interface{})
	for _, instanceSecretFile := range instanceSecretFiles {
		if instanceSecretFile.IsDir() {
			continue
		}
		serviceInstanceSecretPath := path.Join(serviceInstancePath, instanceSecretFile.Name())
		var secretContent []byte
		secretContent, err := ioutil.ReadFile(serviceInstanceSecretPath)
		if err != nil {
			return nil, fmt.Errorf("cannot read secret file '%s' from '%s': %w", instanceSecretFile.Name(), serviceInstanceSecretPath, err)
		}
		var v interface{}
		if err := yaml.Unmarshal(secretContent, &v); err == nil {
			instanceCredentialsMap[instanceSecretFile.Name()] = v
		} else {
			fmt.Printf("cannot unmarshal content of secret file '%s' from '%s': %s", instanceSecretFile.Name(), serviceInstanceSecretPath, err)
			instanceCredentialsMap[instanceSecretFile.Name()] = string(secretContent)
		}
	}
	instanceCredentialsJSON, err := json.Marshal(instanceCredentialsMap)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal map into json: %w", err)
	}
	return instanceCredentialsJSON, nil
}

// GetClientID implements the auth.OAuthConfig interface.
func (c Identity) GetClientID() string {
	return c.ClientID
}

// GetClientSecret implements the auth.OAuthConfig interface.
func (c Identity) GetClientSecret() string {
	return c.ClientSecret
}

// GetURL implements the auth.OAuthConfig interface.
func (c Identity) GetURL() string {
	return c.URL
}

// GetDomains implements the auth.OAuthConfig interface.
func (c Identity) GetDomains() []string {
	return c.Domains
}

// GetZoneUUID implements the auth.OAuthConfig interface.
func (c Identity) GetZoneUUID() uuid.UUID {
	return c.ZoneUUID
}

// GetProofTokenURL implements the auth.OAuthConfig interface.
func (c Identity) GetProofTokenURL() string {
	return c.ProofTokenURL
}

// GetOsbURL implements the auth.OAuthConfig interface.
func (c Identity) GetOsbURL() string {
	return c.OsbURL
}

// GetCertificate implements the auth.OAuthConfig interface.
func (c Identity) GetCertificate() string {
	return c.Certificate
}

// GetKey implements the auth.OAuthConfig interface.
func (c Identity) GetKey() string {
	return c.Key
}

// GetCertificateExpiresAt implements the auth.OAuthConfig interface.
func (c Identity) GetCertificateExpiresAt() string {
	return c.CertificateExpiresAt
}
