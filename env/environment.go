// SPDX-FileCopyrightText: 2020 Felix Blass <felix.blass@sap.com>
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"os"
	"strings"
)

// Interface Pollution? Only use if a external package needs to create own implementations which has to be worked on in this package
// Define this interface on the consumer side? There I will need to work on a more generic basis on different
//type ServiceConfiguration interface {
//	GetClientID() string
//	GetClientSecret() string
//	GetSbURL() string
//	parseEnv(credentials map[string]interface{})
//}

type Platform string

const (
	CLOUD_FOUNDRY Platform = "CF"
	KUBERNETES    Platform = "KUBERNETES"
)

func getPlatform() Platform {
	if strings.TrimSpace(os.Getenv("VCAP_APPLICATION")) != "" {
		return CLOUD_FOUNDRY
	} else {
		return KUBERNETES
	}
}
