/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package dagent

import (
	"github.com/emersion/go-smtp"
)

var ErrLocalErrorInProcessingError = &smtp.SMTPError{
	Code:         451,
	EnhancedCode: smtp.EnhancedCodeNotSet,
	Message:      "Local error in processing",
}

var ErrServiceNotAvailable = &smtp.SMTPError{
	Code:         421,
	EnhancedCode: smtp.EnhancedCodeNotSet,
	Message:      "Service not available",
}

var ErrRequestedActioNotTaken = &smtp.SMTPError{
	Code:         553,
	EnhancedCode: smtp.EnhancedCodeNotSet,
	Message:      "Requested action not taken: mailbox name not allowed",
}

var ErrTransactionFailed = &smtp.SMTPError{
	Code:         554,
	EnhancedCode: smtp.EnhancedCode{5, 0, 0},
	Message:      "Error: transaction failed",
}
