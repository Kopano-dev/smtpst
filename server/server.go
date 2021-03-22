/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jpillora/backoff"
	"github.com/sirupsen/logrus"
)

// Server is our HTTP server implementation.
type Server struct {
	config *Config

	logger logrus.FieldLogger

	httpClient *http.Client
}

// NewServer constructs a server from the provided parameters.
func NewServer(c *Config) (*Server, error) {
	s := &Server{
		config: c,
		logger: c.Logger,

		httpClient: &http.Client{},
	}

	return s, nil
}

// Serve starts all the accociated servers resources and listeners and blocks
// forever until signals or error occurs.
func (server *Server) Serve(ctx context.Context) error {
	var err error

	serveCtx, serveCtxCancel := context.WithCancel(ctx)
	defer serveCtxCancel()

	logger := server.logger

	errCh := make(chan error, 2)
	exitCh := make(chan struct{}, 1)
	signalCh := make(chan os.Signal, 1)
	readyCh := make(chan struct{}, 1)
	triggerCh := make(chan bool, 1)
	authCh := make(chan *DomainsClaims)

	go func() {
		select {
		case <-serveCtx.Done():
			return
		case <-readyCh:
		}
		logger.WithFields(logrus.Fields{}).Infoln("ready")
	}()

	go func() {
		close(readyCh)
	}()

	eventCh := make(chan *TextEvent, 128)
	go func() {
		var domainsClaims *DomainsClaims
		for {
			select {
			case <-serveCtx.Done():
				return

			case currentEvent := <-eventCh:
				switch currentEvent.Event {
				case "domains":
					newDomainsClaims, parseErr := server.parseDomainsToken(currentEvent.Data)
					if parseErr != nil {
						logger.WithError(parseErr).WithField("event", currentEvent.Event).Warnln("failed to parse token data")
						continue
					}
					domainsClaims = newDomainsClaims
					logger.WithFields(logrus.Fields{
						"domains":    domainsClaims.Domains,
						"session_id": domainsClaims.sessionID,
					}).Debugln("domains event received")
					authCh <- domainsClaims

				case "receive":
					var route RouteMeta
					if parseErr := json.Unmarshal([]byte(currentEvent.Data), &route); parseErr != nil {
						logger.WithError(parseErr).WithField("event", currentEvent.Event).Warnln("failed to parse JSON data")
						continue
					}
					if handleErr := server.handleReceiveRoute(serveCtx, domainsClaims, &route); handleErr != nil {
						logger.WithError(handleErr).WithField("event", currentEvent.Event).Warnln("failed to process route")
						continue
					}

				default:
					logger.WithField("event", currentEvent.Event).Warnln("unknown event type")
				}

			case <-time.After(time.Minute):

			}

			if domainsClaims.expiration.Add(-15 * time.Minute).Before(time.Now()) {
				if refreshErr := server.refreshDomainsToken(serveCtx, domainsClaims); refreshErr != nil {
					logger.WithError(refreshErr).Warnln("failed to refresh token")

					if domainsClaims.expiration.Before(time.Now()) {
						errCh <- fmt.Errorf("token expired: %w", refreshErr)
					}
				}
			}
		}
	}()

	go func() {
		defer close(exitCh)

		u := server.config.APIBaseURI.ResolveReference(&url.URL{
			Path: "/v0/smtpst/session",
		})
		params := &url.Values{}
		for _, domain := range server.config.Domains {
			params.Add("domain", domain)
		}
		u.RawQuery = params.Encode()

		var domainsClaims *DomainsClaims

		connector := func() error {
			logger.Debugln("connecting session")
			request, _ := http.NewRequestWithContext(serveCtx, http.MethodPost, u.String(), nil)
			secret := os.Getenv("SMTPST_SECRET_DEV")
			if secret != "" {
				request.SetBasicAuth("dev", secret)
			}

			response, requestErr := server.httpClient.Do(request)
			if requestErr != nil {
				return fmt.Errorf("failed to create smtpst session: %w", requestErr)
			}

			reader := bufio.NewReader(response.Body)
			defer response.Body.Close()

			switch response.StatusCode {
			case http.StatusOK:
				// All good.
			case http.StatusNotAcceptable:
				if domainsClaims != nil {
					// Throw away current session data as server demed them not acceptable.
					domainsClaims = nil
					logger.WithField("session_id", domainsClaims.sessionID).Warnln("failed to resume smtpst session, clearing session data")
					return fmt.Errorf("failed to create smtpst session with not acceptable response: %d", response.StatusCode)
				}
				fallthrough
			default:
				return fmt.Errorf("failed to create smtpst session with unexpected status: %d", response.StatusCode)
			}

			logger.Debugln("session connection established")

			stopCh := make(chan struct{})
			defer close(stopCh)
			go func() {
				for {
					select {
					case <-stopCh:
						return
					case domainsClaims = <-authCh:
						logger.WithField("session_id", domainsClaims.sessionID).Debugln("session data updated")
					}
				}
			}()

			separator := []byte{':', ' '}
			currentEvent := &TextEvent{}
			for {
				lineBytes, readErr := reader.ReadBytes('\n')
				if readErr != nil {
					return fmt.Errorf("failed to read: %w", readErr)
				}

				if len(lineBytes) < 2 {
					continue
				}

				lineBytesParts := bytes.SplitN(lineBytes, separator, 2)
				if len(lineBytesParts[0]) == 0 {
					continue // Ignore comments like ": heartbeat"
				}

				switch string(lineBytesParts[0]) {
				case "data":
					currentEvent.Data = string(bytes.TrimSpace(lineBytesParts[1]))
					select {
					case eventCh <- currentEvent:
					default:
						logger.Warnln("event channel full, ignored event") // TODO(longsleep): Log some parts of the actual data.
					}
					currentEvent = &TextEvent{}

				case "event":
					currentEvent.Event = string(bytes.TrimSpace(lineBytesParts[1]))
				}
			}
		}

		bo := &backoff.Backoff{
			Min:    1 * time.Second,
			Max:    60 * time.Second,
			Factor: 3,
			Jitter: true,
		}

		for {
			connErr := connector()
			if connErr != nil {
				logger.WithError(connErr).Errorln("session connection error")
			} else {
				bo.Reset()
			}

			select {
			case <-serveCtx.Done():
				return
			case <-time.After(bo.Duration()):
			}

			if domainsClaims != nil {
				logger.WithField("session_id", domainsClaims.sessionID).Debugln("reusing existing session")
				params.Del("domains")
				for _, domain := range domainsClaims.Domains {
					params.Add("domain", domain)
				}
				params.Set("sid", domainsClaims.sessionID)
				params.Set("domain_token_hint", domainsClaims.raw)
				u.RawQuery = params.Encode()
			}
		}
	}()

	// Wait for error, with support for HUP to reload
	err = func() error {
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		for {
			select {
			case errFromChannel := <-errCh:
				return errFromChannel
			case reason := <-signalCh:
				if reason == syscall.SIGHUP {
					logger.Infoln("reload signal received, scanning licenses")
					select {
					case triggerCh <- true:
					default:
					}
					continue
				}
				logger.WithField("signal", reason).Warnln("received signal")
				return nil
			}
		}
	}()

	// Shutdown, server will stop to accept new connections, requires Go 1.8+.
	logger.Infoln("clean server shutdown start")

	// Cancel our own context,
	serveCtxCancel()
	func() {
		for {
			select {
			case <-exitCh:
				logger.Infoln("clean server shutdown complete, exiting")
				return
			default:
				// Some services still running
				logger.Info("waiting services to exit")
			}
			select {
			case reason := <-signalCh:
				logger.WithField("signal", reason).Warn("received signal")
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()

	return err
}
