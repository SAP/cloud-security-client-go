// SPDX-FileCopyrightText: 2020-2021 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const iasServiceName = "identity"
const iasSecretKeyDefault = "credentials"
const vcapServicesEnvKey = "VCAP_SERVICES"
const iasConfigPathKey = "IAS_CONFIG_PATH"
const iasConfigPathDefault = "/etc/secrets/sapbtp/identity"

// VCAPServices is the Cloud Foundry environment variable that stores information about services bound to the application
type VCAPServices struct {
	Identity []struct {
		Credentials DefaultIdentity `json:"credentials"`
	} `json:"identity"`
}

// Identity interface has to be implemented to instantiate NewMiddleware. For IAS the standard implementation IASConfig from ../env/iasConfig.go package can be used.
type Identity interface {
	GetClientID() string             // Returns the client id of the oAuth client.
	GetClientSecret() string         // Returns the client secret. Optional
	GetURL() string                  // Returns the url to the DefaultIdentity tenant. E.g. https://abcdefgh.accounts.ondemand.com
	GetDomains() []string            // Returns the domains of the DefaultIdentity service. E.g. ["accounts.ondemand.com"]
	GetZoneUUID() uuid.UUID          // Returns the zone uuid. Optional
	GetProofTokenURL() string        // Returns the proof token url. Optional
	GetCertificate() string          // Returns the client certificate. Optional
	GetKey() string                  // Returns the client certificate key. Optional
	GetCertificateExpiresAt() string // Returns the client certificate expiration time. Optional
	IsCertificateBased() bool        // Returns true, in case GetCertificate() and GetKey returns non empty values
}

// DefaultIdentity represents the parsed credentials from the ias binding
type DefaultIdentity struct {
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

// ParseIdentityConfig parses the IAS config from the applications environment
func ParseIdentityConfig() (Identity, error) {
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

func readServiceBindings(secretPath string) ([]DefaultIdentity, error) {
	instancesBound, err := os.ReadDir(secretPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read service directory '%s' for identity service: %w", secretPath, err)
	}
	identities := []DefaultIdentity{}
	for _, instanceBound := range instancesBound {
		if !instanceBound.IsDir() {
			continue
		}
		serviceInstancePath := path.Join(secretPath, instanceBound.Name())
		instanceSecretFiles, err := os.ReadDir(serviceInstancePath)
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
		identity := DefaultIdentity{}
		if err := json.Unmarshal(instanceSecretsJSON, &identity); err != nil {
			return nil, fmt.Errorf("cannot unmarshal json content in directory '%s' for '%s' service instance: %w", serviceInstancePath, iasServiceName, err)
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

func readCredentialsFileToJSON(serviceInstancePath string, instanceSecretFiles []os.DirEntry) ([]byte, error) {
	for _, instanceSecretFile := range instanceSecretFiles {
		if !instanceSecretFile.IsDir() && instanceSecretFile.Name() == iasSecretKeyDefault {
			serviceInstanceCredentialsPath := path.Join(serviceInstancePath, instanceSecretFile.Name())
			credentials, err := os.ReadFile(serviceInstanceCredentialsPath)
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

func readSecretFilesToJSON(serviceInstancePath string, instanceSecretFiles []os.DirEntry) ([]byte, error) {
	instanceCredentialsMap := make(map[string]interface{})
	for _, instanceSecretFile := range instanceSecretFiles {
		if instanceSecretFile.IsDir() {
			continue
		}
		serviceInstanceSecretPath := path.Join(serviceInstancePath, instanceSecretFile.Name())
		var secretContent []byte
		secretContent, err := os.ReadFile(serviceInstanceSecretPath)
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

// GetClientID implements the env.Identity interface.
func (c DefaultIdentity) GetClientID() string {
	return c.ClientID
}

// GetClientSecret implements the env.Identity interface.
func (c DefaultIdentity) GetClientSecret() string {
	return c.ClientSecret
}

// GetURL implements the env.Identity interface.
func (c DefaultIdentity) GetURL() string {
	return c.URL
}

// GetDomains implements the env.Identity interface.
func (c DefaultIdentity) GetDomains() []string {
	return c.Domains
}

// GetZoneUUID implements the env.Identity interface.
func (c DefaultIdentity) GetZoneUUID() uuid.UUID {
	return c.ZoneUUID
}

// GetProofTokenURL implements the env.Identity interface.
func (c DefaultIdentity) GetProofTokenURL() string {
	return c.ProofTokenURL
}

// GetOsbURL implements the env.Identity interface.
func (c DefaultIdentity) GetOsbURL() string {
	return c.OsbURL
}

// GetCertificate implements the env.Identity interface.
func (c DefaultIdentity) GetCertificate() string {
	return c.Certificate
}

// IsCertificateBased implements the env.Identity interface.
func (c DefaultIdentity) IsCertificateBased() bool {
	return c.Certificate != "" && c.Key != ""
}

// GetKey implements the env.Identity interface.
func (c DefaultIdentity) GetKey() string {
	return c.Key
}

// GetCertificateExpiresAt implements the env.Identity interface.
func (c DefaultIdentity) GetCertificateExpiresAt() string {
	return c.CertificateExpiresAt
}
