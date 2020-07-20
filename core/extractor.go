// SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Cloud Security Client Go contributors
//
// SPDX-License-Identifier: Apache-2.0

package core

import (
	jwtRequest "github.com/dgrijalva/jwt-go/v4/request"
	"net/http"
)

func extractRawToken(r *http.Request) (string, error) {
	rawToken, e := jwtRequest.AuthorizationHeaderExtractor.ExtractToken(r)
	if e != nil {
		return "", e
	}
	return rawToken, nil
}
