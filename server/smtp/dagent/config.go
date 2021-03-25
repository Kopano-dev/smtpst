/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package dagent

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

// Config bundles dagent configuration settings.
type Config struct {
	Context context.Context
	Logger  logrus.FieldLogger
	Router  Router

	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	MaxMessageBytes int
	MaxRecipients   int

	LMTP bool
}
