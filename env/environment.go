package env

import (
	"github.com/cloudfoundry-community/go-cfenv"
	"log"
	"os"
	"strings"
)

// possible combinations:
// xsuaa + cf
// xsuaa + kubernetes
// ias + cf
// ias + kubernetes

type CloudEnvironment interface {
	getClientID() string
	getClientSecret() string
	getSbURL() string
	Parse(credentials map[string]interface{})
}

//
//type CloudEnvironment struct {
//	platform   Platform
//	authServer AuthServer
//}
//
//type Platform string
//type AuthServer string
//
//const (
//	CLOUD_FOUNDRY Platform   = "CLOUD_FOUNDRY"
//	KUBERNETES    Platform   = "KUBERNETES"
//	XSUAA         AuthServer = "XSUAA"
//	IAS           AuthServer = "IAS"
//)

func GetEnvironment() CloudEnvironment {
	var config CloudEnvironment
	if strings.TrimSpace(os.Getenv("VCAP_APPLICATION")) != "" {
		// Cloud Foundry
		appEnv, e := cfenv.Current()
		if e != nil {
			log.Fatal("Could not read cf env")
		}

		xsuaa, e := appEnv.Services.WithName("xsuaa")
		if e != nil {
			log.Fatal("No xsuaa instance bound to the application")
		} else {
			config = XsuaaConfig{}
			config.Parse(xsuaa.Credentials)
		}

	} else {
		// kubernetes (supposably, as no other platforms are known so far)
	}
	return config
}
