package env

import (
	"github.com/cloudfoundry-community/go-cfenv"
	"log"
	//"github.com/lestrrat-go/jwx/jwt"
)

type IASConfig struct {
	clientID     string
	clientSecret string
	baseURL      string
}

func getIASConfig() *IASConfig {
	config := IASConfig{}
	switch getPlatform() {
	case CLOUD_FOUNDRY:
		appEnv, e := cfenv.Current()
		if e != nil {
			log.Fatal("Could not read cf env")
		}
		ias, e := appEnv.Services.WithName("iasb")
		if e != nil {
			log.Fatal("No ias instance bound to the application")
		} else {
			config = IASConfig{}
			config.parseEnv(ias.Credentials)
		}
		// do stuff
	case KUBERNETES:
		// do stuff
	}
	return &config
}

func (c IASConfig) GetClientID() string {
	return c.clientID
}

func (c IASConfig) GetClientSecret() string {
	return c.clientSecret
}

func (c IASConfig) GetBaseURL() string {
	return c.baseURL
}

func (c *IASConfig) parseEnv(credentials map[string]interface{}) {
	(*c).clientID = credentials["username"].(string)
	(*c).clientSecret = credentials["password"].(string)
}
