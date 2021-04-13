/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/status"
	"stash.kopano.io/kgol/smtpst/internal/ipc"
	"stash.kopano.io/kgol/smtpst/server"
)

func commandStatus() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status [...args]",
		Short: "Show service status",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runStatus(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cwd, _ := os.Getwd()

	statusCmd.Flags().StringVar(&defaultStatePath, "state-path", cwd, "Full path to writable state directory")
	statusCmd.Flags().Bool("json", false, "Output status as JSON")

	return statusCmd
}

func runStatus(cmd *cobra.Command, args []string) error {
	if err := applyFlagsFromEnvFile(cmd, nil); err != nil {
		return err
	}

	statePath, err := filepath.Abs(defaultStatePath)
	if err != nil {
		return fmt.Errorf("state-path invalid: %w", err)
	}

	ipc.MustInitializeStatusSHM(statePath, "")

	err = status.Run(cmd, args)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("failed to fetch status, is smtpstd running?")
		}
	}
	return err
}

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
	} else {
		logger.Debugln("server status stored to shm successfully")
	}
}

func clearStatus() error {
	return ipc.ClearStatus()
}
