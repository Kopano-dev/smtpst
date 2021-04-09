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
	"path/filepath"
	"strings"

	systemDaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/spf13/cobra"
	"stash.kopano.io/kgol/ksurveyclient-go/autosurvey"

	"stash.kopano.io/kgol/smtpst/server"
	"stash.kopano.io/kgol/smtpst/version"
)

var (
	defaultLogTimestamp     = true
	defaultLogLevel         = "info"
	defaultSystemdNotify    = false
	defaultProviderURL      = ""
	defaultDomains          = []string{}
	defaultDAgentListenAddr = "127.0.0.1:10025"
	defaultSMTPLocalAddr    = "127.0.0.1:25"
	defaultStatePath        = ""
	defaultLicensesPath     = "/etc/kopano/licenses"
	defaultIss              = ""
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

	cwd, _ := os.Getwd()

	serveCmd.Flags().BoolVar(&defaultLogTimestamp, "log-timestamp", defaultLogTimestamp, "Prefix each log line with timestamp")
	serveCmd.Flags().StringVar(&defaultLogLevel, "log-level", defaultLogLevel, "Log level (one of panic, fatal, error, warn, info or debug)")
	serveCmd.Flags().BoolVar(&defaultSystemdNotify, "systemd-notify", defaultSystemdNotify, "Enable systemd sd_notify callback")
	serveCmd.Flags().StringVar(&defaultProviderURL, "provider-url", defaultProviderURL, "URL to the SMTP secure transport provider API")
	serveCmd.Flags().StringArrayVar(&defaultDomains, "domain", defaultDomains, "Domain to receive for")
	serveCmd.Flags().StringVar(&defaultDAgentListenAddr, "dagent-listen", defaultDAgentListenAddr, "TCP listen address for SMTP delivery agent")
	serveCmd.Flags().StringVar(&defaultSMTPLocalAddr, "smtp-local", defaultSMTPLocalAddr, "TCP address for local SMTP")
	serveCmd.Flags().StringVar(&defaultStatePath, "state-path", cwd, "Full path to writable state directory")
	serveCmd.Flags().StringVar(&defaultLicensesPath, "licenses-path", defaultLicensesPath, "Path to the folder containing Kopano license files")
	serveCmd.Flags().StringVar(&defaultIss, "iss", defaultIss, "OIDC issuer URL")

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

	if defaultStatePath == "" {
		return fmt.Errorf("state-path must not be empty")
	}
	if info, statErr := os.Stat(defaultStatePath); statErr != nil || !info.IsDir() {
		return fmt.Errorf("state-path error or not a directory: %w", statErr)
	}

	issURL, err := url.Parse(defaultIss)
	if err != nil {
		return fmt.Errorf("invalid iss: %w", err)
	}

	cfg := &server.Config{
		Iss: issURL,

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

		DAgentListenAddress: defaultDAgentListenAddr,

		SMTPLocalAddr: defaultSMTPLocalAddr,
	}

	cfg.StatePath, err = filepath.Abs(defaultStatePath)
	if err != nil {
		return fmt.Errorf("state-path invalid: %w", err)
	}

	cfg.LicensesPath, err = filepath.Abs(defaultLicensesPath)
	if err != nil {
		return fmt.Errorf("licenses-path invalid: %w", err)
	}

	for _, domain := range defaultDomains {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			du, parseErr := url.Parse("http://" + domain)
			if parseErr != nil {
				return fmt.Errorf("invalid domain value: %s", domain)
			}
			if domain != du.Host {
				return fmt.Errorf("domain value is not a domain: %s", domain)
			}
			cfg.Domains = append(cfg.Domains, domain)
		}
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		return err
	}

	// Survey support.
	var guid []byte
	if cfg.Iss != nil && cfg.Iss.Hostname() != "localhost" {
		guid = []byte(cfg.Iss.String())
	}
	err = autosurvey.Start(ctx,
		"smtpstd",
		version.Version,
		guid,
	)
	if err != nil {
		return fmt.Errorf("failed to start auto survey: %v", err)
	}

	return srv.Serve(ctx)
}
