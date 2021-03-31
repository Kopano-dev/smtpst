/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"net/http"

	"stash.kopano.io/kgol/smtpst/version"
)

var defaultUserAgent = "smtpstd/" + version.Version

func withUserAgent(req *http.Request) *http.Request {
	req.Header.Set("User-Agent", defaultUserAgent)
	return req
}
