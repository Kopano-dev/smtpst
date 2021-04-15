/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package gen

import (
	"github.com/spf13/cobra"
)

// DefaultRootUse defines the root cmmand Use value to use for generators.
var DefaultRootUse = "kopano-smtpstd"

func CommandGen() *cobra.Command {
	genCmd := &cobra.Command{
		Use:   "gen [...args]",
		Short: "A collection of useful generators",
	}

	genCmd.AddCommand(CommandMan())
	genCmd.AddCommand(CommandAutoComplete())

	return genCmd
}
