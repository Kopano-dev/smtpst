/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package status

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/common"
	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/serve"
	"stash.kopano.io/kgol/smtpst/internal/ipc"
)

func CommandStatus() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status [...args]",
		Short: "Show service status",
		Run: func(cmd *cobra.Command, args []string) {
			if err := status(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	statusCmd.Flags().StringVar(&serve.DefaultStatePath, "state-path", serve.DefaultStatePath, "Full path to writable state directory")
	statusCmd.Flags().Bool("json", false, "Output status as JSON")

	return statusCmd
}

func status(cmd *cobra.Command, args []string) error {
	if err := common.ApplyFlagsFromEnvFile(cmd, nil); err != nil {
		return err
	}

	statePath, err := filepath.Abs(serve.DefaultStatePath)
	if err != nil {
		return fmt.Errorf("state-path invalid: %w", err)
	}

	ipc.MustInitializeStatusSHM(statePath, "")

	err = Run(cmd, args)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("failed to fetch status, is smtpstd running?")
		}
	}
	return err
}
