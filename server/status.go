/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"sync"
	"time"

	"github.com/jinzhu/copier"
)

type Status struct {
	sync.RWMutex

	HTTPProviderURL string `json:"provider_url"`
	HTTPConnected   bool   `json:"provider_connected"`

	SessionID  *string    `json:"session_id"`
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
	if domainsClaims != nil {
		status.Lock()
		defer status.Unlock()
		sessionID := domainsClaims.sessionID
		status.SessionID = &sessionID
		status.Domains = append(status.Domains, domainsClaims.Domains...)
		expiration := domainsClaims.expiration
		status.Expiration = &expiration
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

	return status, nil
}
