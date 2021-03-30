/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package dagent

import (
	"context"
	"io"

	"github.com/emersion/go-smtp"
)

type Router interface {
	Mail(from string, opts smtp.MailOptions) error
	GetRoute(domain string) (Route, error)
}

type Route interface {
	Mail(ctx context.Context, from string, opts smtp.MailOptions) error
	Rcpt(ctx context.Context, rcptTo string) error
	Data(ctx context.Context, r io.Reader) error
}
