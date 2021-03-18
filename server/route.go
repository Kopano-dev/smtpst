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
	"os"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/sirupsen/logrus"
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

	from := response.Header.Get("X-Smtpst-From")
	rcptTo := response.Header["X-Smtpst-Rcptto"]

	server.logger.WithFields(logrus.Fields{
		"from":    from,
		"rcpt_to": rcptTo,
	}).Debugln("route receive smtp")

	devRcptTo := os.Getenv("SMTPST_DEV_RCPTTO")
	if devRcptTo != "" {
		rcptTo = []string{devRcptTo}
		server.logger.WithField("rcpt_to", rcptTo).Warnln("dev route for all mail in effect")
	}

	sendErr := server.sendMail("127.0.0.1:25", from, rcptTo, response.Body)
	if sendErr != nil {
		server.logger.WithError(sendErr).Warnln("failed to route receive via smtp")
		return sendErr
	}

	return nil
}

func (server *Server) sendMail(addr, from string, to []string, r io.Reader) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if mailErr := c.Mail(from, nil); mailErr != nil {
		return mailErr
	}
	for _, addr := range to {
		if rcptErr := c.Rcpt(addr); rcptErr != nil {
			return rcptErr
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = io.Copy(w, r)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}
