/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package serve

import (
	"stash.kopano.io/kgol/smtpst/internal/ipc"
	"stash.kopano.io/kgol/smtpst/server"
)

func onStatus(srv *server.Server) {
	logger := srv.Logger()

	s, statusErr := srv.Status()
	if statusErr != nil {
		logger.WithError(statusErr).Errorln("failed to get server status")
		s = &server.Status{}
	}

	statusErr = ipc.SetStatus(s)
	if statusErr != nil {
		logger.WithError(statusErr).Errorln("failed to share server status")
	}
}

func clearStatus() error {
	return ipc.ClearStatus()
}
