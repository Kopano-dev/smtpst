/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"sync"
	"time"

	"github.com/jinzhu/copier"
	"stash.kopano.io/kgol/kustomer/license"
)

type Status struct {
	sync.RWMutex

	HTTPProviderURL string   `json:"provider_url"`
	HTTPConnected   bool     `json:"provider_connected"`
	HTTPLicenseLIDs []string `json:"provider_license_ids,omitempty"`

	SessionID  *string    `json:"session_id,omitempty"`
	Domains    []string   `json:"domains"`
	Expiration *time.Time `json:"exp"`
}

func (status *Status) Copy() (*Status, error) {
	status.RLock()
	defer status.RUnlock()

	s := &Status{}
	err := copier.CopyWithOption(s, status, copier.Option{
		IgnoreEmpty: true,
		DeepCopy:    true,
	})

	return s, err
}

func (status *Status) SetDomainsClaims(domainsClaims *DomainsClaims) error {
	status.Lock()
	defer status.Unlock()
	if domainsClaims != nil {
		sessionID := domainsClaims.sessionID
		status.SessionID = &sessionID
		status.Domains = append(status.Domains, domainsClaims.Domains...)
		expiration := domainsClaims.expiration
		status.Expiration = &expiration
	} else {
		status.SessionID = nil
		status.Domains = nil
		status.Expiration = nil
	}

	return nil
}

func (status *Status) SetLicenseClaims(licenseClaims []*license.Claims) error {
	status.Lock()
	defer status.Unlock()
	status.HTTPLicenseLIDs = make([]string, 0)
	for _, lc := range licenseClaims {
		status.HTTPLicenseLIDs = append(status.HTTPLicenseLIDs, lc.LicenseID)
	}

	return nil
}

func (server *Server) Status() (*Status, error) {
	server.status.RLock()
	status, err := server.status.Copy()
	server.status.RUnlock()
	if err != nil {
		return nil, err
	}

	err = status.SetDomainsClaims(server.getDomainsClaims())
	if err != nil {
		return nil, err
	}

	err = status.SetLicenseClaims(server.getLicenseClaims())
	if err != nil {
		return nil, err
	}

	return status, nil
}
