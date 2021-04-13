/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package status

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"

	"stash.kopano.io/kgol/smtpst/internal/ipc"
	"stash.kopano.io/kgol/smtpst/server"
)

type errMsg error

type statusMsg *server.Status

type model struct {
	ctx context.Context

	spinner spinner.Model

	quitting bool

	status *server.Status
	err    error
}

func initialModel(ctx context.Context) *model {
	s := spinner.NewModel()
	s.HideFor = time.Second
	s.Spinner = spinner.Line
	return &model{
		ctx: ctx,

		spinner: s,
	}
}

func (m *model) getStatus() tea.Msg {
	var err error
	var s *server.Status

	count := 0
	for {
		s, err = ipc.GetStatus()
		if err == nil {
			break
		}

		if count >= 3 {
			return errMsg(err)
		}
		log.Println(err.Error())

		select {
		case <-m.ctx.Done():
			return errMsg(m.ctx.Err())
		case <-time.After(1 * time.Second):
		}

		count++
	}

	return statusMsg(s)
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(
		spinner.Tick,
		m.getStatus,
	)
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		default:
			return m, nil
		}

	case errMsg:
		m.err = msg
		return m, tea.Quit

	case statusMsg:
		m.status = msg
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	default:
		return m, nil
	}
}

func (m *model) View() string {
	if m.err != nil {
		// We do not display any errors here.
		return ""
	}
	if m.status != nil {
		// We do not display the status here.
		return ""
	}

	var str string

	s := termenv.String(m.spinner.View()).String()
	str = fmt.Sprintf("%s Fetching smtpst status ...", s)

	if m.quitting {
		return str + "\n"
	}
	return str
}
