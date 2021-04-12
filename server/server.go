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
	"errors"
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
	"stash.kopano.io/kgol/kustomer"
	"stash.kopano.io/kgol/kustomer/license"

	"stash.kopano.io/kgol/smtpst/server/smtp/dagent"
)

// Server is our HTTP server implementation.
type Server struct {
	mutex sync.RWMutex

	config *Config

	logger logrus.FieldLogger

	domainsClaims      *DomainsClaims
	domainsClaimsMutex sync.RWMutex

	httpClient *http.Client
	DAgent     *dagent.DAgent

	readyCh  chan struct{}
	updateCh chan struct{}
	eventCh  chan *TextEvent

	licenseClaims []*license.Claims
}

// NewServer constructs a server from the provided parameters.
func NewServer(c *Config) (*Server, error) {
	s := &Server{
		config: c,
		logger: c.Logger,

		readyCh:  make(chan struct{}, 1),
		updateCh: make(chan struct{}),
		eventCh:  make(chan *TextEvent, 128),
	}

	certificate, err := s.loadCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// TLS client configuration.
	s.httpClient = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        1,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 60 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
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
		ReadTimeout:     60 * time.Second,
		WriteTimeout:    60 * time.Second,
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
	triggerCh := make(chan bool, 1)

	serveCtx, serveCtxCancel := context.WithCancel(ctx)
	defer serveCtxCancel()

	logger := server.logger

	go func() {
		select {
		case <-serveCtx.Done():
			return
		case <-server.readyCh:
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
		pumpErr := server.incomingEventsReadPump(serveCtx)
		if pumpErr != nil {
			errCh <- pumpErr
		}
	}()

	serversWg.Add(1)
	// Start and maintain a connection with the smtpst-provider
	go func() {
		defer serversWg.Done()
		startErr := server.startSMTPSTSession(serveCtx)
		if startErr != nil {
			errCh <- startErr
		}
	}()

	// Load license files directly.
	// TODO(longsleep): Once available, maube retrieve license from kustomerd.
	serversWg.Add(1)
	go func() {
		defer serversWg.Done()
		loadHistory := make(map[string]*license.Claims)
		activateHistory := make(map[string]*license.Claims)
		var lastSub string
		var first bool = true
		f := func() error {
			var sub string
			var claims []*license.Claims
			var changed bool
			// Load and parse license files.
			if server.config.LicensesPath != "" {
				scanner := &kustomer.LicensesLoader{
					Offline:         true, // We don't load any key set, so set always to offline.
					Logger:          logger,
					LoadHistory:     loadHistory,
					ActivateHistory: activateHistory,
					OnRemove: func(c *license.Claims) {
						logger.WithField("id", c.LicenseID).Debugln("removed license, triggering")
						changed = true
					},
					OnNew: func(c *license.Claims) {
						logger.WithField("id", c.LicenseID).Debugln("found new license, triggering")
						changed = true
					},
				}
				var scanErr error
				claims, scanErr = scanner.UnsafeScanFolderWithoutVerification(server.config.LicensesPath, jwt.Expected{
					Time: time.Now(),
				})
				if scanErr != nil {
					if first {
						return fmt.Errorf("failed to scan for licenses: %w", scanErr)
					}
					logger.WithError(scanErr).Errorln("failed to scan for licenses")
				}
			}

			// Find suitable claims.
			var selectedClaims []*license.Claims
			var groupwareFallback = true
			for _, c := range claims {
				// TODO(longsleep): Add smtpst specific product.
				if _, ok := c.Kopano.Products["smtpst"]; ok {
					if groupwareFallback {
						selectedClaims = make([]*license.Claims, 0)
						groupwareFallback = false
					}
					selectedClaims = append(selectedClaims, c)
					continue
				}
				if _, ok := c.Kopano.Products["groupware"]; ok && groupwareFallback {
					selectedClaims = append(selectedClaims, c)
					continue
				}
			}

			// Find sub.
			if len(selectedClaims) > 0 {
				sub = selectedClaims[0].Claims.Subject
			}
			if !first && sub == lastSub && !changed {
				return nil
			}
			lastSub = sub

			// Update active license claims.
			server.mutex.Lock()
			server.licenseClaims = selectedClaims
			updateCh := server.updateCh
			server.updateCh = make(chan struct{})
			server.mutex.Unlock()

			if first {
				// Set ready.
				close(server.readyCh)
				first = false
			}
			close(updateCh)
			return nil
		}
		select {
		case <-serveCtx.Done():
			return
		default:
			if triggerErr := f(); triggerErr != nil {
				errCh <- triggerErr
				return
			}
		}
		for {
			select {
			case <-serveCtx.Done():
				return
			case <-triggerCh:
				_ = f()
			case <-time.After(60 * time.Second):
				select {
				case <-triggerCh:
				default:
				}
				_ = f()
			}
		}
	}()

	// Wait for all services to stop before closing the exit channel
	go func() {
		serversWg.Wait()
		logger.Infoln("clean smtpst-provider connection shutdown complete")
		close(exitCh)
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
				if _, replaced, err := server.replaceDomainsClaims(domainsClaims); err != nil {
					logger.WithError(err).Errorln("failed to set domains claims")
				} else if replaced {
					logger.WithFields(logrus.Fields{
						"domains":    newDomainsClaims.Domains,
						"session_id": newDomainsClaims.sessionID,
					}).Infoln("domains updated")
				}

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

		if domainsClaims != nil && domainsClaims.expiration.Add(-15*time.Minute).Before(time.Now()) {
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

	updater := func(currentLicenseClaims []*license.Claims) error {
		allowDomains := server.getDevSecretFromEnv() != ""
		if !allowDomains && len(currentLicenseClaims) > 0 {
			if _, ok := currentLicenseClaims[0].Kopano.Products["groupware"]; !ok {
				// Not a groupware license, let's allow domains and let the provider decide.
				allowDomains = true
			}
		}

		params := url.Values{}
		if domainsClaims := server.getDomainsClaims(); domainsClaims == nil {
			for _, domain := range server.config.Domains {
				params.Add("domain", domain)
			}
			if !allowDomains {
				if domains := params["domain"]; len(domains) > 0 {
					return fmt.Errorf("domains requested, but no suitable license available")
				}
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
		return nil
	}

	var sessionMutex sync.RWMutex
	var sessionCtx context.Context
	var sessionCtxCancel context.CancelFunc
	var sessionClaims []*license.Claims
	var sessionCh = make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-server.updateCh:
			}

			server.mutex.RLock()
			currentLicenseClaims := server.licenseClaims
			server.mutex.RUnlock()

			sessionMutex.Lock()
			currentsessionCtxCancel := sessionCtxCancel
			currentSessionCh := sessionCh
			sessionCh = make(chan struct{})
			sessionCtx, sessionCtxCancel = context.WithCancel(ctx)
			if len(currentLicenseClaims) > 0 {
				sessionClaims = currentLicenseClaims
			} else {
				sessionClaims = make([]*license.Claims, 0)
			}
			sessionMutex.Unlock()
			close(currentSessionCh)
			if currentsessionCtxCancel != nil {
				currentsessionCtxCancel()
			}
		}
	}()

	select {
	case <-server.readyCh:
	case <-ctx.Done():
		return nil
	}

session:
	for {
		sessionMutex.RLock()
		currentSessionCtx := sessionCtx
		currentSessionClaims := sessionClaims
		currentSessionCh := sessionCh
		sessionMutex.RUnlock()
		if currentSessionClaims == nil {
			select {
			case <-ctx.Done():
				return nil
			case <-currentSessionCh:
				continue session
			}
		}

		if updateErr := updater(currentSessionClaims); updateErr != nil {
			logger.WithError(updateErr).Errorln("failed to configure session")
			sessionMutex.Lock()
			sessionClaims = nil
			sessionCh = make(chan struct{})
			sessionMutex.Unlock()
			continue session
		}

		if connErr := server.receiveFromSMTPSTSession(currentSessionCtx, sessionURL, currentSessionClaims); connErr != nil {
			if errors.Is(connErr, context.Canceled) {
				logger.Infoln("session closed by client")
			} else {
				logger.WithError(connErr).Errorln("session connection error")
			}
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
func (server *Server) receiveFromSMTPSTSession(ctx context.Context, u *url.URL, currentLicenseClaims []*license.Claims) error {
	logger := server.logger

	logger.Debugln("connecting session")

	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)

	secret := server.getDevSecretFromEnv()
	if secret != "" {
		logger.Warnln("authenticating session with dev secret")
		request.SetBasicAuth("dev", secret)
	} else if len(currentLicenseClaims) > 0 {
		logger.WithField("id", currentLicenseClaims[0].LicenseID).Infoln("authenticating session with license claims")
		request.Header.Set("Authorization", "Bearer "+string(currentLicenseClaims[0].Raw))
		for _, clc := range currentLicenseClaims[1:] {
			request.Header.Set("X-Smtpst-License", string(clc.Raw))
		}
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

func (server *Server) getDevSecretFromEnv() string {
	return os.Getenv("SMTPST_SECRET_DEV")
}
