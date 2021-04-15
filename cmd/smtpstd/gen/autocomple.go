/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package gen

import (
	"os"

	"github.com/spf13/cobra"
)

func CommandAutoComplete() *cobra.Command {
	completionCmd := &cobra.Command{
		Use:   "autocomplete [bash|zsh|fish]",
		Short: "Generate shell autocompletion script",
		Long: `To load completions:

Bash:

  $ source <(kopano-smtpstd completion bash)

  # To load completions for each session, execute once:
  $ kopano-smtpstd completion bash > /etc/bash_completion.d/kopano-smtpstd

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ kopano-smtpstd completion zsh > "${fpath[1]}/_kopano-smtpstd"

  # You will need to start a new shell for this setup to take effect.

fish:

  $ kopano-smtpstd completion fish | source

  # To load completions for each session, execute once:
  $ kopano-smtpstd completion fish > ~/.config/fish/completions/kopano-smtpstd.fish

`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish"},
		Args:                  cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			root := cmd.Root()
			root.Use = DefaultRootUse

			switch args[0] {
			case "bash":
				root.GenBashCompletion(os.Stdout)
			case "zsh":
				root.GenZshCompletion(os.Stdout)
			case "fish":
				root.GenFishCompletion(os.Stdout, true)
			}
		},
	}

	return completionCmd
}
