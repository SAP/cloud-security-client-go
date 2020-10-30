// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"os"
	"strings"
)

type Platform string

const (
	CLOUD_FOUNDRY Platform = "CF"
	KUBERNETES    Platform = "KUBERNETES"
)

func getPlatform() Platform {
	if strings.TrimSpace(os.Getenv("VCAP_SERVICES")) != "" {
		return CLOUD_FOUNDRY
	} else {
		return KUBERNETES
	}
}
