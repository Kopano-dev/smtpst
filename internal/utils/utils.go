/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package utils

import (
	"fmt"
	"strings"
	"sync/atomic"
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

type AtomicBool int32

func (b *AtomicBool) IsSet() bool { return atomic.LoadInt32((*int32)(b)) != 0 }
func (b *AtomicBool) SetTrue()    { atomic.StoreInt32((*int32)(b), 1) }
func (b *AtomicBool) SetFalse()   { atomic.StoreInt32((*int32)(b), 0) }
