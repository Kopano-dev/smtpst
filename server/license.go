/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"stash.kopano.io/kgol/kustomer/license"
)

func (server *Server) getLicenseClaims() []*license.Claims {
	server.licenseClaimsMutex.RLock()
	defer server.licenseClaimsMutex.RUnlock()
	return server.licenseClaims
}

// updatelicenseClaims updates active license claims.
func (server *Server) updatelicenseClaims(licenseClaims []*license.Claims) {
	server.licenseClaimsMutex.Lock()
	defer server.licenseClaimsMutex.Unlock()

	server.licenseClaims = licenseClaims
	updateCh := server.updateCh
	server.updateCh = make(chan struct{})

	close(updateCh)
}
