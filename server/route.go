/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"context"
	"io"

	"github.com/emersion/go-smtp"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Route struct {
	domain string

	logger logrus.FieldLogger

	server *Server

	mail *RouteMail
}

type RouteMail struct {
	from   string
	body   smtp.BodyType
	size   int
	utf8   bool
	rcptTo []string
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
	if route.mail == nil {
		route.mail = &RouteMail{}
	}

	route.mail.from = from
	route.mail.body = opts.Body
	route.mail.size = opts.Size
	route.mail.utf8 = opts.UTF8
	return nil
}

func (route *Route) Rcpt(ctx context.Context, rcptTo string) error {
	if route.mail == nil {
		route.mail = &RouteMail{}
	}

	route.mail.rcptTo = append(route.mail.rcptTo, rcptTo)
	return nil
}

func (route *Route) Data(ctx context.Context, reader io.Reader) error {
	return route.server.handleRequestSend(ctx, reader, route.mail)
}
