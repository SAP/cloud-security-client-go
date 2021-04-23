// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"net/http"
	"strings"
)

const authorization string = "Authorization"

func extractRawToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get(authorization)

	if authHeader != "" {
		splitAuthHeader := strings.Fields(strings.TrimSpace(authHeader))
		if strings.ToLower(splitAuthHeader[0]) == "bearer" && len(splitAuthHeader) == 2 {
			return splitAuthHeader[1], nil
		}
	}

	return "", errors.New("extracting token from request header failed")
}
