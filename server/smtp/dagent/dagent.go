/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package dagent

import (
	"context"
	"net"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/lithammer/shortuuid/v3"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/sirupsen/logrus"

	"stash.kopano.io/kgol/smtpst/internal/utils"
)

type DAgent struct {
	ctx    context.Context
	logger logrus.FieldLogger
	router Router

	sessionContext       context.Context
	sessionContextCancel context.CancelFunc
	inShutdown           utils.AtomicBool

	s        *smtp.Server
	sessions cmap.ConcurrentMap
}

var _ smtp.Backend = (*DAgent)(nil) // Verify that *DAgent implements smtp.Backend.

func New(config *Config) (*DAgent, error) {
	logger := config.Logger.WithFields(logrus.Fields{
		"scope": "dagent",
	})

	sessionContext, sessionContextCancel := context.WithCancel(context.Background())

	da := &DAgent{
		ctx:    config.Context,
		logger: logger,
		router: config.Router,

		sessionContext:       sessionContext,
		sessionContextCancel: sessionContextCancel,

		sessions: cmap.New(),
	}

	da.s = smtp.NewServer(da)
	da.s.AuthDisabled = true
	da.s.ReadTimeout = config.ReadTimeout
	da.s.WriteTimeout = config.WriteTimeout
	da.s.MaxMessageBytes = config.MaxMessageBytes
	da.s.MaxRecipients = config.MaxRecipients
	da.s.ErrorLog = logger
	da.s.LMTP = config.LMTP

	return da, nil
}

func (da *DAgent) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	return nil, smtp.ErrAuthUnsupported
}

func (da *DAgent) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	if da.inShutdown.IsSet() {
		return nil, ErrServiceNotAvailable
	}

	sessionID := shortuuid.New()
	session, err := NewSession(da.sessionContext, sessionID, da.router, da.logger, da.onLogout)
	if err != nil {
		da.logger.WithError(err).WithField("session_id", sessionID).Errorln("failed to create SMTP session")
		return nil, ErrLocalErrorInProcessingError
	}
	da.sessions.Set(sessionID, session)

	return session, nil
}

// Serve accepts incoming connections on the Listener l.
func (da *DAgent) Serve(l net.Listener) error {
	return da.s.Serve(l)
}

func (da *DAgent) Shutdown(ctx context.Context) error {
	da.inShutdown.SetTrue()
	da.sessionContextCancel()

	func() {
		for {
			if da.sessions.Count() == 0 {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	return da.s.Close()
}

func (da *DAgent) onLogout(session *Session) {
	da.sessions.Remove(session.id)
}
