// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"os"
	"strings"
)

// Platform holds the type string of the platform the application runs on
type Platform string

const (
	cloudFoundry Platform = "CLOUD_FOUNDRY"
	kubernetes   Platform = "KUBERNETES"
	unknown      Platform = "UNKNOWN"
)

func getPlatform() Platform {
	switch {
	case strings.TrimSpace(os.Getenv("VCAP_SERVICES")) != "":
		return cloudFoundry
	case false: // kubernetes not yet supported
		return kubernetes
	default:
		return unknown
	}
}
