/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// Server is our HTTP server implementation.
type Server struct {
	config *Config

	logger logrus.FieldLogger
}

// NewServer constructs a server from the provided parameters.
func NewServer(c *Config) (*Server, error) {
	s := &Server{
		config: c,
		logger: c.Logger,
	}

	return s, nil
}

// Serve starts all the accociated servers resources and listeners and blocks
// forever until signals or error occurs.
func (s *Server) Serve(ctx context.Context) error {
	var err error

	serveCtx, serveCtxCancel := context.WithCancel(ctx)
	defer serveCtxCancel()

	logger := s.logger

	errCh := make(chan error, 2)
	exitCh := make(chan struct{}, 1)
	signalCh := make(chan os.Signal, 1)
	readyCh := make(chan struct{}, 1)
	triggerCh := make(chan bool, 1)

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

	// Add stuff here.
	go func() {
		defer close(exitCh)

		c := &http.Client{}
		request, _ := http.NewRequestWithContext(serveCtx, http.MethodPost, "https://mose4:10443/v0/smtpst/session", nil)
		request.SetBasicAuth("dev", "secret")
		response, requestErr := c.Do(request)
		if requestErr != nil {
			errCh <- fmt.Errorf("failed to create smtpst session: %w", requestErr)
			return
		}

		reader := bufio.NewReader(response.Body)
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			errCh <- fmt.Errorf("failed to create smtpst session with unexpected status: %d", response.StatusCode)
			return
		}

		separator := []byte{':', ' '}
		currentEvent := &TextEvent{}
		for {
			lineBytes, readErr := reader.ReadBytes('\n')
			if readErr != nil {
				errCh <- fmt.Errorf("failed to read: %w", readErr)
				return
			}

			if len(lineBytes) < 2 {
				continue
			}

			lineBytesParts := bytes.SplitN(lineBytes, separator, 2)
			// data: {"domain":"lala.dev.kopano.xyz","id":"8d32d625-ed55-4ca3-ac7a-02560bfa32fb","exp":1616060125}
			if len(lineBytesParts[0]) == 0 {
				continue // Ignore comments like ": heartbeat"
			}

			switch string(lineBytesParts[0]) {
			case "data":
				currentEvent.Data = string(lineBytesParts[1])
				logger.Debugf("xxx received event: %s, %s", currentEvent.Event, currentEvent.Data)

				currentEvent = &TextEvent{}

			case "event":
				currentEvent.Event = string(lineBytesParts[1])
			}
		}

		logger.Debugln("xxx response", response)
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
