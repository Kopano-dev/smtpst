/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package status

import (
	"encoding/json"
	"io"

	"stash.kopano.io/kgol/smtpst/server"
)

func outputJSON(w io.Writer, status *server.Status) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}
