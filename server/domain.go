/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
	domainsClaims.expiration = claims.Expiry.Time()
	domainsClaims.raw = raw

	return domainsClaims, nil
}

func (server *Server) refreshDomainsToken(ctx context.Context, domainsClaims *DomainsClaims) error {
	u := server.config.APIBaseURI.ResolveReference(&url.URL{
		Path: "/v0/smtpst/session/" + domainsClaims.sessionID,
	})

	request, _ := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), nil)
	request.Header.Set("Authorization", "Bearer "+domainsClaims.raw)

	server.logger.Debugln("refreshing token")
	response, requestErr := server.httpClient.Do(request)
	if requestErr != nil {
		return fmt.Errorf("failed refresh token: %w", requestErr)
	}
	response.Body.Close()

	if response.StatusCode == http.StatusNotModified {
		server.logger.Debugln("tried to refresh token too early")
	} else if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to refresh token with unexpected status: %d", response.StatusCode)
	}
	server.logger.Debugln("refresh triggered")

	return nil
}
