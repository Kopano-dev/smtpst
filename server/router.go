/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/sirupsen/logrus"

	"stash.kopano.io/kgol/smtpst/server/smtp/dagent"
)

var (
	errRouteDomainUnknown = errors.New("unknown domain in route")
	errRouteExpired       = errors.New("route is expired")
)

func (server *Server) Mail(from string, opts smtp.MailOptions) error {
	return nil
}

func (server *Server) GetRoute(domain string) (dagent.Route, error) {
	return &Route{
		domain: domain,
		logger: server.logger,
		server: server,
	}, nil
}

// handleReceiveRoute Handles a new route sent by the server, requests the data and sends the received e-mail to the local smtp server.
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

	logger := server.logger.WithFields(logrus.Fields{
		"domain": route.Domain,
		"id":     route.ID,
	})

	u := server.config.APIBaseURI.ResolveReference(&url.URL{
		Path: "/v0/smtpst/session/" + domainsClaims.sessionID + "/route/" + route.ID + "/receive",
	})

	err := func() error {
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
		request.Header.Set("Authorization", "Bearer "+domainsClaims.raw)
		logger.Debugln("route requesting receive")
		response, requestErr := server.httpClient.Do(request)
		if requestErr != nil {
			return fmt.Errorf("failed to request route receive: %w", requestErr)
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to request route receive, unexpected response status: %d", response.StatusCode)
		}

		from := response.Header.Get("X-Smtpst-From")
		rcptTo := response.Header["X-Smtpst-Rcptto"]

		smtpLogger := logger.WithFields(logrus.Fields{
			"from":    from,
			"rcpt_to": rcptTo,
		})
		smtpLogger.Debugln("route routing receive smtp start")
		devRcptTo := os.Getenv("SMTPST_DEV_RCPTTO")
		if devRcptTo != "" {
			rcptTo = []string{devRcptTo}
			logger.WithField("rcpt_to", rcptTo).Warnln("dev route for all mail in effect")
		}
		err := server.sendMail(server.config.SMTPLocalAddr, from, rcptTo, response.Body)
		if err != nil {
			smtpLogger.WithError(err).Warnln("failed to route receive via smtp")
		} else {
			smtpLogger.Debugln("route routing receive smtp success")
		}

		return err
	}()
	// Send status to server.
	status := &RouteStatus{
		Success: err == nil,
	}
	if err != nil {
		if e, ok := err.(*smtp.SMTPError); ok {
			status.Code = e.Code
			status.EnhancedCode = e.EnhancedCode
			status.Message = e.Message
		} else {
			status.Message = err.Error()
		}
	}

	err = func() error {
		statusBuf := &bytes.Buffer{}
		if encodeErr := json.NewEncoder(statusBuf).Encode(status); encodeErr != nil {
			return fmt.Errorf("failed to encode route receive status: %w", encodeErr)
		}

		request, _ := http.NewRequestWithContext(ctx, http.MethodPatch, u.String(), statusBuf)
		request.Header.Set("Authorization", "Bearer "+domainsClaims.raw)
		logger.Debugln("route sending route receive status")
		response, requestErr := server.httpClient.Do(request)
		if requestErr != nil {
			return fmt.Errorf("failed to send route receive status: %w", requestErr)
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusNoContent {
			return fmt.Errorf("failed to send route receive status, unexpected response status: %d", response.StatusCode)
		} else {
			logger.Debugln("route sending route receive complete")
		}

		return nil
	}()
	if err != nil {
		logger.WithError(err).Warnln("route sending route receive error, mail might be duplicated")
	}

	return nil
}

// sendMail connects to an smtp server and delivers an email to it.
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

// routeMail Routes an email through the smtpst-provider to be delivered to its destination.
func (server *Server) routeMail(ctx context.Context, reader io.Reader, from string, rcptTo []string, size int, utf8 bool, body smtp.BodyType) error {
	logger := server.logger
	domainsClaims := server.getDomainsClaims()

	sendUrl := server.config.APIBaseURI.ResolveReference(&url.URL{
		Path: "/v0/smtpst/session/" + domainsClaims.sessionID + "/send",
	})

	logger.Debugln("sending mail request...")
	err := func() error {
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, sendUrl.String(), reader)
		request.Header.Set("Authorization", "Bearer "+domainsClaims.raw)
		request.Header.Set("Content-Type", "text/x-smtpst-routed-smtp")
		request.Header.Set("X-Smtpst-From", from)
		for _, rcptTo := range rcptTo {
			request.Header.Add("X-Smtpst-Rcptto", rcptTo)
		}
		if utf8 {
			request.Header.Set("X-Smtpst-Utf8", "1")
		}
		request.Header.Set("X-Smtpst-Body", string(body))
		if size > 0 {
			request.Header.Set("Content-Length", strconv.Itoa(size))
		}

		response, requestErr := server.httpClient.Do(request)
		if requestErr != nil {
			return fmt.Errorf("failed to request send mail: %w", requestErr)
		}

		defer response.Body.Close()

		if response.StatusCode != http.StatusCreated {
			return fmt.Errorf("failed to request send mail, unexpected response status: %d", response.StatusCode)
		}

		return nil
	}()

	logger.Debugln("sending mail request done")

	return err
}
