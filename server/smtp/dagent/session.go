/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package dagent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/emersion/go-smtp"
	"github.com/sirupsen/logrus"

	"stash.kopano.io/kgol/smtpst/utils"
)

type Session struct {
	ctx context.Context
	id  string

	router   Router
	logger   logrus.FieldLogger
	onLogout SessionCb

	routes  map[string]Route
	domains map[string][]string

	from string
	opts *smtp.MailOptions
}

type SessionCb func(session *Session)

func NewSession(ctx context.Context, sessionID string, router Router, logger logrus.FieldLogger, onLogout SessionCb) (*Session, error) {
	return &Session{
		ctx:    ctx,
		id:     sessionID,
		router: router,
		logger: logger.WithFields(logrus.Fields{
			"scope":      "dagent-session",
			"session_id": sessionID,
		}),
		onLogout: onLogout,

		routes:  make(map[string]Route),
		domains: make(map[string][]string),
	}, nil
}

var _ smtp.Session = (*Session)(nil) // Verify that *Session implements smtp.Session.

func (s *Session) Mail(from string, opts smtp.MailOptions) error {
	s.logger.WithField("from", from).Debugln("mail from")

	s.from = from
	s.opts = &opts

	return s.router.Mail(from, opts)
}

func (s *Session) Rcpt(rcptTo string) error {
	s.logger.WithField("rcptTo", rcptTo).Debugln("mail rcptTo")
	domain, err := utils.GetDomainFromEmail(rcptTo)
	if err != nil {
		s.logger.WithError(err).Debugln("invalid rcpt to value")
		return ErrRequestedActioNotTaken
	}

	s.domains[domain] = append(s.domains[domain], rcptTo)

	return nil
}

func (s *Session) Data(r io.Reader) error {
	s.logger.Debugf("smpt mail data")

	route, routeErr := s.router.GetRoute("")
	if routeErr != nil {
		s.logger.WithError(routeErr).Errorln("failed to get smtp route")
	}
	if route == nil {
		s.logger.Warnln("no smtp route available")
		return ErrServiceNotAvailable
	}

	if routeErr = route.Mail(s.ctx, s.from, *s.opts); routeErr != nil {
		s.logger.WithError(routeErr).Errorln("smtp route error on mail")
		return routeErr
	}

	for _, rcptTos := range s.domains {
		for _, rcptTo := range rcptTos {
			if routeErr = route.Rcpt(s.ctx, rcptTo); routeErr != nil {
				s.logger.WithError(routeErr).Errorln("smtp route error on rcptTo")
				return routeErr
			}
		}
	}

	if routeErr = route.Data(s.ctx, r); routeErr != nil {
		s.logger.WithError(routeErr).Errorln("smtp data route error on data")
		return routeErr
	}

	s.logger.Debugln("smpt mail data done")
	return nil
}

func (s *Session) LMTPData(r io.Reader, status smtp.StatusCollector) error {
	data, err := io.ReadAll(r)
	if err != nil {
		s.logger.WithError(err).Errorln("lmtp data failed to read")
		return ErrTransactionFailed
	}

	var wg sync.WaitGroup
	var concurrency = make(chan struct{}, 5)

	wg.Add(len(s.domains))
domainsLoop:
	for domain, rcptTos := range s.domains {
		select {
		case <-s.ctx.Done():
			wg.Done()
			continue domainsLoop
		case concurrency <- struct{}{}:
		}
		go func(d string, a []string) {
			s.logger.Debugf("lmtp data: %s, %v", d, a)
			route, routeErr := s.router.GetRoute(d)
			if routeErr != nil {
				s.logger.WithError(routeErr).Errorln("lmtp data failed to get smtp route")
			}
			defer func() {
				var result error
				if routeErr != nil {
					result = ErrServiceNotAvailable
				}
				for _, rcptTo := range a {
					s.logger.WithError(routeErr).WithFields(logrus.Fields{
						"domain": d,
						"status": result,
						"rcptTo": rcptTo,
					}).Debugln("lmtp set status")
					status.SetStatus(rcptTo, result)
				}
				<-concurrency
				wg.Done()
			}()

			if route == nil {
				s.logger.WithField("domain", d).Warnln("lmtp data found no available smtp route")
				if routeErr == nil {
					routeErr = errors.New("no route")
				}
				return
			}

			if routeErr = route.Mail(s.ctx, s.from, *s.opts); routeErr != nil {
				s.logger.WithError(routeErr).Errorln("lmtp data route error on mail")
				return
			}

			for _, rcptTo := range a {
				if routeErr = route.Rcpt(s.ctx, rcptTo); routeErr != nil {
					break
				}
			}
			if routeErr != nil {
				s.logger.WithError(routeErr).Errorln("lmtp data route error on rcptTo")
				return
			}

			routeErr = route.Data(s.ctx, bytes.NewBuffer(data))
			if routeErr != nil {
				s.logger.WithError(routeErr).Errorln("lmtp data route error on data")
				return
			}
		}(domain, rcptTos)
	}
	wg.Wait()
	s.logger.Debugln("lmtp data done")

	return nil
}

func (s *Session) Reset() {
	s.logger.Debugln("mail reset")

	s.routes = make(map[string]Route)
	s.domains = make(map[string][]string)

	s.from = ""
	s.opts = nil
}

func (s *Session) Logout() error {
	s.logger.Debugln("mail logout")
	if s.onLogout != nil {
		s.onLogout(s)
	}
	return nil
}
