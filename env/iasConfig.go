// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"errors"
	"fmt"
	"github.com/cloudfoundry-community/go-cfenv"
	"strings"
)

const iasServiceName = "identity"

// IASConfig represents the parsed credentials from the ias binding
type IASConfig struct {
	ClientID     string
	ClientSecret string
	Domain       string
	URL          string
}

// GetIASConfig parses the IAS config from the applications environment
func GetIASConfig() (*IASConfig, error) {
	config := IASConfig{}
	switch getPlatform() {
	case CLOUD_FOUNDRY:
		appEnv, e := cfenv.Current()
		if e != nil {
			return nil, fmt.Errorf("could not read cf env")
		}
		ias, e := appEnv.Services.WithLabel(iasServiceName)
		if e != nil {
			return nil, fmt.Errorf("no '" + iasServiceName + "' service instance bound to the application")
		} else if len(ias) > 1 {
			return nil, fmt.Errorf("more than one '" + iasServiceName + "' service instance bound to the application")
		} else {
			config = IASConfig{}
			e := config.parseEnv(ias[0].Credentials)
			if e != nil {
				return nil, fmt.Errorf("error during parsing of "+iasServiceName+" environment: %v", e)
			}
		}
	case KUBERNETES:
		return nil, fmt.Errorf("unable to parse ias config: kubernetes env detected but not yet supported")
	default:
		return nil, fmt.Errorf("unable to parse ias config: unknown environment detected")
	}
	return &config, nil

}

// GetIASConfigInUserProvidedService parses the user-provided IAS config from the applications environment
func GetIASConfigInUserProvidedService(serviceInstanceName string) (*IASConfig, error) {
	config := IASConfig{}
	switch getPlatform() {
	case CLOUD_FOUNDRY:
		appEnv, e := cfenv.Current()
		if e != nil {
			return nil, fmt.Errorf("could not read cf env")
		}
		userProvided, e := appEnv.Services.WithLabel("user-provided")
		if e != nil {
			return nil, fmt.Errorf("no " + iasServiceName + " instance bound to the application")
		}

		var instance cfenv.Service
		var found bool
		for _, service := range userProvided {
			if strings.EqualFold(serviceInstanceName, service.Name) {
				if !found {
					found = true
					instance = service
				} else {
					return nil, fmt.Errorf("more than one user-provided service with name '" + serviceInstanceName + "' bound to the application")
				}
			}
		}

		e = config.parseEnv(instance.Credentials)
		if e != nil {
			return nil, fmt.Errorf("error during parsing of "+serviceInstanceName+" in user-provided environment: ", e)
		}
	case KUBERNETES:
		return nil, fmt.Errorf("unable to parse ias config: kubernetes env detected but not yet supported")
	default:
		return nil, fmt.Errorf("unable to parse ias config: unknown environment detected")
	}
	return &config, nil
}

// GetClientID implements the auth.OAuthConfig interface.
func (c IASConfig) GetClientID() string {
	return c.ClientID
}

// GetClientSecret implements the auth.OAuthConfig interface.
func (c IASConfig) GetClientSecret() string {
	return c.ClientSecret
}

// GetURL implements the auth.OAuthConfig interface.
func (c IASConfig) GetURL() string {
	return c.URL
}

// GetDomain implements the auth.OAuthConfig interface.
func (c IASConfig) GetDomain() string {
	return c.Domain
}

func (c *IASConfig) parseEnv(credentials map[string]interface{}) error {
	clientID, ok := credentials["clientid"]
	if !ok {
		return errors.New("unable to find property clientid in environment")
	}
	c.ClientID = clientID.(string)

	clientSecret, ok := credentials["clientsecret"]
	if !ok {
		return errors.New("unable to find property clientsecret in environment")
	}
	c.ClientSecret = clientSecret.(string)

	baseURL, ok := credentials["url"]
	if !ok {
		return errors.New("unable to find property url in environment")
	}
	c.URL = baseURL.(string)

	domain, ok := credentials["domain"]
	if !ok {
		return errors.New("unable to find property domain in environment")
	}
	c.Domain = domain.(string)
	return nil
}
