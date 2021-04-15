/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2018 Kopano and its licensors
 */

package main

import (
	"fmt"
	"os"

	"stash.kopano.io/kgol/smtpst/cmd"
	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/common"
	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/gen"
	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/serve"
	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/status"
)

func main() {
	cmd.RootCmd.Use = "smtpstd"

	cmd.RootCmd.PersistentFlags().StringVarP(&common.DefaultEnvConfigFile, "config", "c", common.DefaultEnvConfigFile, "Full path to config file")

	cmd.RootCmd.AddCommand(serve.CommandServe())
	cmd.RootCmd.AddCommand(status.CommandStatus())
	cmd.RootCmd.AddCommand(gen.CommandGen())

	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
