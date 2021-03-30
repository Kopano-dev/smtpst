/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"net/url"

	"github.com/sirupsen/logrus"
)

// Config bundles configuration settings.
type Config struct {
	Logger logrus.FieldLogger

	OnReady func(*Server)

	APIBaseURI *url.URL

	Domains []string

	DAgentListenAddress string

	SMTPLocalAddr string
}
