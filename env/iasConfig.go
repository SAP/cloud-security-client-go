package env

import (
	"errors"
	"github.com/cloudfoundry-community/go-cfenv"
	"log"
)

const serviceName = "identity-beta"

type IASConfig struct {
	ClientId     string
	ClientSecret string
	URL          string
}

func GetIASConfig() *IASConfig {
	config := IASConfig{}
	switch getPlatform() {
	case CLOUD_FOUNDRY:
		appEnv, e := cfenv.Current()
		if e != nil {
			log.Fatal("Could not read cf env")
		}
		ias, e := appEnv.Services.WithLabel(serviceName)
		if e != nil {
			userProvided, e := appEnv.Services.WithLabel("user-provided")
			if e != nil {
				log.Fatal("No " + serviceName + " instance bound to the application")
			}
			ias, ok := userProvided[0].Credentials["identity-beta"]
			if !ok {
				log.Fatal("No " + serviceName + " instance bound to the application")
			}
			credentials := ias.([]interface{})[0].(map[string]interface{})["credentials"].(map[string]interface{})
			e = config.parseEnv(credentials)
			if e != nil {
				log.Fatal("error during parsing of "+serviceName+" in user-provided environment: ", e)
			}
		} else {
			config = IASConfig{}
			e := config.parseEnv(ias[0].Credentials)
			if e != nil {
				log.Fatal("error during parsing of "+serviceName+" environment: ", e)
			}
		}
		// do stuff
	case KUBERNETES:
		log.Fatal("kubernetes env detected but not yet supported")
		// do stuff
	}
	return &config
}

func (c IASConfig) GetClientID() string {
	return c.ClientId
}

func (c IASConfig) GetClientSecret() string {
	return c.ClientSecret
}

func (c IASConfig) GetURL() string {
	return c.URL
}

func (c *IASConfig) parseEnv(credentials map[string]interface{}) error {
	if clientID, ok := credentials["clientid"]; !ok {
		return errors.New("unable to find property clientid in environment")
	} else {
		c.ClientId = clientID.(string)
	}
	if clientSecret, ok := credentials["clientsecret"]; !ok {
		return errors.New("unable to find property clientsecret in environment")
	} else {
		c.ClientSecret = clientSecret.(string)
	}
	if baseURL, ok := credentials["url"]; !ok {
		return errors.New("unable to find property url in environment")
	} else {
		c.URL = baseURL.(string)
	}
	return nil
}
