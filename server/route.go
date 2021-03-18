/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

type RouteMeta struct {
	Domain string           `json:"domain"`
	ID     string           `json:"id"`
	Expiry *jwt.NumericDate `json:"exp"`
}

var (
	errRouteDomainUnknown = errors.New("unknown domain in route")
	errRouteExpired       = errors.New("route is expired")
)

func (server *Server) handleReceiveRoute(ctx context.Context, domainsClaims *DomainsClaims, route *RouteMeta) error {
	server.logger.Debugln("xxx handleReceiveRoute", *domainsClaims, *route)

	valid := false
	for _, domain := range domainsClaims.Domains {
		if domain == route.Domain {
			valid = true
			break
		}
	}
	if !valid {
		return errRouteDomainUnknown
	}

	if route.Expiry.Time().Before(time.Now()) {
		return errRouteExpired
	}

	u := server.config.APIBaseURI.ResolveReference(&url.URL{
		Path: "/v0/smtpst/session/" + domainsClaims.sessionID + "/route/" + route.ID + "/receive",
	})
	c := &http.Client{}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	request.Header.Set("Authorization", "Bearer "+domainsClaims.raw)
	server.logger.WithField("url", u.String()).Debugln("requesting route receive")
	response, requestErr := c.Do(request)
	if requestErr != nil {
		return fmt.Errorf("failed to request route receive: %w", requestErr)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to request route receive with unexpected status: %d", response.StatusCode)
	}

	data, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return fmt.Errorf("error while reading route receive data: %w", readErr)
	}

	server.logger.WithField("data", string(data)).Debugln("xxx route receive data")

	return nil
}
