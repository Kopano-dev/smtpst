/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"time"
)

type Status struct {
	HTTPProviderURL string `json:"provider_url"`
	HTTPConnected   bool   `json:"provider_connected"`

	SessionID  *string    `json:"session_id"`
	Domains    []string   `json:"domains"`
	Expiration *time.Time `json:"exp"`
}

func (server *Server) Status() (*Status, error) {
	status := &Status{
		HTTPProviderURL: server.config.APIBaseURI.String(),
	}

	server.domainsClaimsMutex.RLock()
	domainsClaims := server.domainsClaims
	server.domainsClaimsMutex.RUnlock()

	server.mutex.RLock()
	defer server.mutex.RUnlock()
	status.HTTPConnected = server.httpConnected

	if domainsClaims != nil {
		sessionID := domainsClaims.sessionID
		status.SessionID = &sessionID
		status.Domains = append(status.Domains, domainsClaims.Domains...)
		expiration := domainsClaims.expiration
		status.Expiration = &expiration
	}

	return status, nil
}
