/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/emersion/go-smtp"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Route struct {
	logger logrus.FieldLogger

	server *Server

	from   string
	rcptTo []string
	size   int
	utf8   bool
	body   smtp.BodyType
}

type RouteMeta struct {
	Domain string           `json:"domain"`
	ID     string           `json:"id"`
	Expiry *jwt.NumericDate `json:"exp"`
}

type RouteStatus struct {
	Success bool `json:"success"`

	Code         int               `json:"code"`
	EnhancedCode smtp.EnhancedCode `json:"enhanced_code,omitempty"`
	Message      string            `json:"message"`
}

func (route *Route) Mail(ctx context.Context, from string, opts smtp.MailOptions) error {
	route.from = from
	route.body = opts.Body
	route.size = opts.Size
	route.utf8 = opts.UTF8
	return nil
}

func (route *Route) Rcpt(ctx context.Context, rcptTo string) error {
	route.rcptTo = append(route.rcptTo, rcptTo)
	return nil
}

func (route *Route) Data(ctx context.Context, reader io.Reader) error {
	domainsClaims := route.server.getDomainsClaims()
	httpClient := route.server.httpClient

	sendURL := route.server.config.APIBaseURI.ResolveReference(&url.URL{
		Path: "/v0/smtpst/session/" + domainsClaims.sessionID + "/send",
	})

	logger := route.logger.WithFields(logrus.Fields{
		"session_id": domainsClaims.sessionID,
		"from":       route.from,
		"rcpt_to":    route.rcptTo,
	})
	logger.Debugln("route mail")

	err := func() error {
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, sendURL.String(), reader)
		request.Header.Set("Authorization", "Bearer "+domainsClaims.raw)
		request.Header.Set("Content-Type", "text/x-smtpst-routed-smtp")
		request.Header.Set("X-Smtpst-From", route.from)
		for _, rcptTo := range route.rcptTo {
			request.Header.Add("X-Smtpst-Rcptto", rcptTo)
		}
		if route.utf8 {
			request.Header.Set("X-Smtpst-Utf8", "1")
		}
		request.Header.Set("X-Smtpst-Body", string(route.body))
		if route.size > 0 {
			request.Header.Set("Content-Length", strconv.Itoa(route.size))
		}

		response, requestErr := httpClient.Do(request)
		if requestErr != nil {
			return fmt.Errorf("failed to request send mail: %w", requestErr)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusCreated {
			return fmt.Errorf("failed to request send mail, unexpected response status: %d", response.StatusCode)
		}

		return nil
	}()

	logger.Debugln("route mail request done")

	return err
}
