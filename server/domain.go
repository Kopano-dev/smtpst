/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

type DomainsClaims struct {
	Domains []string `json:"domains"`

	raw        string
	expiration time.Time
	sessionID  string
}

func (server *Server) parseDomainsToken(raw string) (*DomainsClaims, error) {
	token, err := jwt.ParseSigned(raw)
	if err != nil {
		return nil, err
	}

	claims := &jwt.Claims{}
	domainsClaims := &DomainsClaims{}
	if err := token.UnsafeClaimsWithoutVerification(claims, domainsClaims); err != nil {
		return nil, err
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 5*time.Minute); err != nil {
		return nil, err
	}

	// Copy over standard claims.
	domainsClaims.sessionID = claims.Subject
	domainsClaims.raw = raw

	return domainsClaims, nil
}
