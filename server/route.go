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
	return route.server.routeMail(ctx, reader, route.from, route.rcptTo, route.size, route.utf8, route.body)
}
