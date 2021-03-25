/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"

	systemDaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/spf13/cobra"

	"stash.kopano.io/kgol/smtpst/server"
)

var (
	defaultLogTimestamp        = true
	defaultLogLevel            = "info"
	defaultSystemdNotify       = false
	defaultProviderURL         = ""
	defaultDomains             = []string{}
	defaultDAgentListenAddress = "127.0.0.1:10025"
)

func commandServe() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve [...args]",
		Short: "Start service",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	serveCmd.Flags().BoolVar(&defaultLogTimestamp, "log-timestamp", defaultLogTimestamp, "Prefix each log line with timestamp")
	serveCmd.Flags().StringVar(&defaultLogLevel, "log-level", defaultLogLevel, "Log level (one of panic, fatal, error, warn, info or debug)")
	serveCmd.Flags().BoolVar(&defaultSystemdNotify, "systemd-notify", defaultSystemdNotify, "Enable systemd sd_notify callback")
	serveCmd.Flags().StringVar(&defaultProviderURL, "provider-url", defaultProviderURL, "URL to the SMTP secure transport provider API")
	serveCmd.Flags().StringArrayVar(&defaultDomains, "domain", defaultDomains, "Domain to receive for")
	serveCmd.Flags().StringVar(&defaultDAgentListenAddress, "dagent-listen", defaultDAgentListenAddress, "TCP listen address for SMTP delivery agent")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger, err := newLogger(!defaultLogTimestamp, defaultLogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	logger.Debugln("serve start")

	apiBaseURL, err := url.Parse(defaultProviderURL)
	if err != nil {
		return fmt.Errorf("invalid provider-url: %w", err)
	}
	if apiBaseURL.Host == "" {
		return fmt.Errorf("provider-url must not be empty")
	}

	cfg := &server.Config{
		Logger: logger,

		OnReady: func(srv *server.Server) {
			if defaultSystemdNotify {
				ok, notifyErr := systemDaemon.SdNotify(false, systemDaemon.SdNotifyReady)
				logger.WithField("ok", ok).Debugln("called systemd sd_notify ready")
				if notifyErr != nil {
					logger.WithError(notifyErr).Errorln("failed to trigger systemd sd_notify")
				}
			}
		},

		APIBaseURI: apiBaseURL,

		Domains: defaultDomains,

		DAgentListenAddress: defaultDAgentListenAddress,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		return err
	}

	return srv.Serve(ctx)
}
