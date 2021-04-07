/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jpillora/backoff"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/jwt"

	"stash.kopano.io/kgol/smtpst/server/smtp/dagent"
)

// Server is our HTTP server implementation.
type Server struct {
	config *Config

	logger logrus.FieldLogger

	domainsClaims      *DomainsClaims
	domainsClaimsMutex sync.RWMutex

	httpClient *http.Client
	DAgent     *dagent.DAgent

	eventCh chan *TextEvent
}

// NewServer constructs a server from the provided parameters.
func NewServer(c *Config) (*Server, error) {
	s := &Server{
		config: c,
		logger: c.Logger,

		eventCh: make(chan *TextEvent, 128),
	}

	certificate, err := s.loadCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// TODO(joao): Make sure configuration is sane and expose what's needed (if
	// any) to the configuration.
	s.httpClient = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          1,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				Rand:         nil,
				Certificates: []tls.Certificate{certificate},
			},
		},
	}

	domainsClaims, err := s.loadDomainsClaims()
	if err != nil {
		if err == jwt.ErrExpired {
			if domainsClaims != nil {
				s.logger.WithFields(logrus.Fields{
					"domains":    domainsClaims.Domains,
					"exp":        domainsClaims.expiration,
					"session_id": domainsClaims.sessionID,
				}).Warnln("stored domains claims are expired, ignored")
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	} else if domainsClaims != nil {
		s.logger.WithFields(logrus.Fields{
			"domains":    domainsClaims.Domains,
			"exp":        domainsClaims.expiration,
			"session_id": domainsClaims.sessionID,
		}).Infoln("loaded domains claims from file")
	}

	dagentConfig := &dagent.Config{
		Logger: s.logger,
		Router: s,
		LMTP:   false,

		// TODO(joao): Expose in configuration.
		ReadTimeout:  10 * time.Minute,
		WriteTimeout: 10 * time.Minute,

		MaxMessageBytes: 32 * 1024 * 1024,
		MaxRecipients:   100,
	}

	s.DAgent, err = dagent.New(dagentConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create dagent server: %w", err)
	}

	return s, nil
}

// Serve starts all the accociated servers resources and listeners and blocks
// forever until signals or error occurs.
func (server *Server) Serve(ctx context.Context) error {
	var err error

	errCh := make(chan error, 2)
	exitCh := make(chan struct{}, 1)
	signalCh := make(chan os.Signal, 1)
	readyCh := make(chan struct{}, 1)
	triggerCh := make(chan bool, 1)

	serveCtx, serveCtxCancel := context.WithCancel(ctx)
	defer serveCtxCancel()

	logger := server.logger

	go func() {
		select {
		case <-serveCtx.Done():
			return
		case <-readyCh:
		}
		logger.WithFields(logrus.Fields{}).Infoln("ready")
	}()

	var serversWg sync.WaitGroup

	// Start DAgent
	dagentListener, listenErr := net.Listen("tcp", server.config.DAgentListenAddress)
	if listenErr != nil {
		return fmt.Errorf("failed to create dagent listener: %w", listenErr)
	}
	serversWg.Add(1)
	go func() {
		defer serversWg.Done()
		logger.WithField("listen_addr", dagentListener.Addr()).Infoln("dagent listener started")
		serveErr := server.DAgent.Serve(dagentListener)
		if serveErr != nil {
			errCh <- serveErr
		}
	}()

	serversWg.Add(1)
	// Parse incomming events
	go func() {
		defer serversWg.Done()
		err := server.incomingEventsReadPump(serveCtx)
		if err != nil {
			errCh <- err
		}
	}()

	serversWg.Add(1)
	// Start and maintain a connection with the smtpst-provider
	go func() {
		defer serversWg.Done()
		err := server.startSMTPSTSession(serveCtx)
		if err != nil {
			errCh <- err
		}
	}()

	// Wait for all services to stop before closing the exit channel
	go func() {
		serversWg.Wait()
		logger.Infoln("clean smtpst-provider connection shutdown complete")
		close(exitCh)
	}()

	// Set ready
	go func() {
		close(readyCh) // TODO(joao): Implement proper ready
	}()

	// Wait for error or signal, with support for HUP to reload
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

	// Shutdown DAgent
	shutdownCtx, shutdownCtxCancel := context.WithTimeout(ctx, 10*time.Second)
	go func() {
		if shutdownErr := server.DAgent.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.WithError(shutdownErr).Warn("clean dagent shutdown failed")
		} else {
			logger.Info("clean dagent shutdown complete")
		}
	}()

	// Cancel our own context and wait for all services to shutdown.
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

	shutdownCtxCancel() // Prevents leak.

	return err
}

// incomingEventsReadPump parses incomming events on the server's event channel.
// If the domains claims token is almost expiring it'll trigger a refresh from
// the server.
// Blocks forever until the contex is close or the domainsclaims expires.
func (server *Server) incomingEventsReadPump(ctx context.Context) error {
	logger := server.logger
	var domainsClaims *DomainsClaims

	for {
		select {
		case <-ctx.Done():
			return nil

		case currentEvent := <-server.eventCh:
			switch currentEvent.Event {
			case "domains":
				newDomainsClaims, parseErr := server.parseDomainsToken(currentEvent.Data)
				if parseErr != nil {
					logger.WithError(parseErr).WithField("event", currentEvent.Event).Warnln("failed to parse token data")
					continue
				}

				domainsClaims = newDomainsClaims
				logger.WithFields(logrus.Fields{
					"domains":    newDomainsClaims.Domains,
					"session_id": newDomainsClaims.sessionID,
				}).Debugln("domains event received")
				server.replaceDomainsClaims(domainsClaims)

			case "receive":
				var route RouteMeta
				if parseErr := json.Unmarshal([]byte(currentEvent.Data), &route); parseErr != nil {
					logger.WithError(parseErr).WithField("event", currentEvent.Event).Warnln("failed to parse JSON data")
					continue
				}
				if handleErr := server.handleReceiveRoute(ctx, domainsClaims, &route); handleErr != nil {
					logger.WithError(handleErr).WithField("event", currentEvent.Event).Warnln("failed to process route")
					continue
				}

			default:
				logger.WithField("event", currentEvent.Event).Warnln("unknown event type")
			}

		case <-time.After(time.Minute):

		}

		if domainsClaims.expiration.Add(-15 * time.Minute).Before(time.Now()) {
			if domainsClaims == server.getDomainsClaims() {
				if refreshErr := server.refreshDomainsToken(ctx, domainsClaims); refreshErr != nil {
					logger.WithError(refreshErr).Warnln("failed to refresh token")

					if domainsClaims.expiration.Before(time.Now()) {
						return fmt.Errorf("token expired: %w", refreshErr)
					}
				}
			}
		}
	}
}

// startSMTPSTSession starts a new sessions with the smtpst-provider and
// maintains it. If disconnected, it'll attempt to reconnect indefinetly.
// Blocks forever until the context is closed.
func (server *Server) startSMTPSTSession(ctx context.Context) error {
	logger := server.logger

	bo := &backoff.Backoff{
		Min:    1 * time.Second,
		Max:    60 * time.Second,
		Factor: 3,
		Jitter: true,
	}
	sessionURL := server.config.APIBaseURI.ResolveReference(&url.URL{
		Path: "/v0/smtpst/session",
	})
	updater := func() {
		params := url.Values{}
		if domainsClaims := server.getDomainsClaims(); domainsClaims == nil {
			for _, domain := range server.config.Domains {
				params.Add("domain", domain)
			}
		} else {
			logger.WithField("session_id", domainsClaims.sessionID).Debugln("reusing existing session")
			for _, domain := range domainsClaims.Domains {
				params.Add("domain", domain)
			}
			params.Set("sid", domainsClaims.sessionID)
			params.Set("domain_token_hint", domainsClaims.raw)
		}
		sessionURL.RawQuery = params.Encode()
	}
	for {
		updater()

		connErr := server.receiveFromSMTPSTSession(ctx, sessionURL)
		if connErr != nil {
			logger.WithError(connErr).Errorln("session connection error")
		} else {
			bo.Reset()
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(bo.Duration()):
		}
	}
}

// receiveFromSMTPSTSession sends an HTTP request for a new session, and listens
// for new events sent through the connection. The event data will be processed
// and pushed to the server's event channel. Blocks forever until the connection
// or the context is closed.
func (server *Server) receiveFromSMTPSTSession(ctx context.Context, u *url.URL) error {
	logger := server.logger

	logger.Debugln("connecting session")

	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	secret := os.Getenv("SMTPST_SECRET_DEV")
	if secret != "" {
		request.SetBasicAuth("dev", secret)
	}

	response, requestErr := server.httpClient.Do(withUserAgent(request))
	if requestErr != nil {
		return fmt.Errorf("failed to create smtpst session: %w", requestErr)
	}

	reader := bufio.NewReader(response.Body)
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
		// All good.
	case http.StatusNotAcceptable:
		// Throw away current session data as connection demed them not acceptable.
		domainsClaims, replaced, err := server.replaceDomainsClaims(nil)
		if err != nil {
			return fmt.Errorf("failed to replace domains claims: %w", err)
		} else if replaced {
			logger.WithField("session_id", domainsClaims.sessionID).Warnln("failed to resume smtpst session, clearing session data")
			return fmt.Errorf("failed to create smtpst session with not acceptable response: %d", response.StatusCode)
		}
		fallthrough
	default:
		return fmt.Errorf("failed to create smtpst session with unexpected status: %d", response.StatusCode)
	}

	logger.Debugln("session connection established")

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
			case server.eventCh <- currentEvent:
			default:
				logger.Warnln("event channel full, ignored event") // TODO(longsleep): Log some parts of the actual data.
			}
			currentEvent = &TextEvent{}

		case "event":
			currentEvent.Event = string(bytes.TrimSpace(lineBytesParts[1]))
		}
	}
}
