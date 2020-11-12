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
	CLOUD_FOUNDRY Platform = "CF"
	KUBERNETES    Platform = "KUBERNETES"
	UNKNOWN       Platform = "UNKNOWN"
)

func getPlatform() Platform {
	switch {
	case strings.TrimSpace(os.Getenv("VCAP_SERVICES")) != "":
		return CLOUD_FOUNDRY
	case 1 == 2:
		return KUBERNETES
	default:
		return UNKNOWN
	}
}
