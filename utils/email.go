/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package utils

import (
	"fmt"
	"strings"
)

// GetDomainFromEmail returns the domain part as defined in RFC 5322 of the
// provided email address.
func GetDomainFromEmail(email string) (string, error) {
	at := strings.LastIndex(email, "@")
	if at >= 0 {
		return email[at+1:], nil
	}

	return "", fmt.Errorf("no @ in value: %v", email)
}
