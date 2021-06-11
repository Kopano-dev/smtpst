/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package status

import (
	"context"
	"io/ioutil"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"stash.kopano.io/kgol/smtpst/server"
)

// Run starts the user interface which fetches the status and displays it.
func Run(cmd *cobra.Command, args []string) error {
	// Fetch status via ui model.
	status, err := func() (*server.Status, error) {
		var opts []tea.ProgramOption

		if !isatty.IsTerminal(os.Stdout.Fd()) {
			// If not a terminal, disable user interface.
			opts = []tea.ProgramOption{tea.WithoutRenderer(), tea.WithInput(nil)}
		} else {
			// If user interface, discard all log output.
			log.SetOutput(ioutil.Discard)
		}

		ctx, ctxCancel := context.WithCancel(context.Background())
		defer ctxCancel()

		model := initialModel(ctx)

		// Start user interface.
		p := tea.NewProgram(model, opts...)
		if err := p.Start(); err != nil {
			return nil, err
		}
		if model.err != nil {
			// Log and return UI error directly.
			log.Println(model.err.Error())
			return nil, model.err
		}

		return model.status, nil
	}()
	if err != nil || status == nil {
		return err
	}

	// Output.
	if ok, _ := cmd.Flags().GetBool("json"); ok {
		// Direct JSON output.
		return outputJSON(os.Stdout, status)
	} else {
		// Formatted text output colors.
		return outputPretty(os.Stdout, status)
	}
}
