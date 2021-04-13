/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ipc

import (
	"stash.kopano.io/kgol/smtpst/server"
)

var (
	implStatus statusImpl
)

type statusImpl interface {
	clear() error
	set(*server.Status) error
	get() (*server.Status, error)
}

// MustInitializeStatusSHM initializes the status module using shared memory.
func MustInitializeStatusSHM(statePath, projectID string) {
	if implStatus != nil {
		panic("ipc status already initialized")
	}

	if statePath == "" {
		panic("state path must not be empty")
	}

	implStatus = &shmStatus{
		statePath: statePath,
		projectID: projectID,
	}
}

func ClearStatus() error {
	return implStatus.clear()
}

func SetStatus(status *server.Status) error {
	return implStatus.set(status)
}

func GetStatus() (*server.Status, error) {
	return implStatus.get()
}
