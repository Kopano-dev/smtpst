/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	systemDaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"stash.kopano.io/kgol/ksurveyclient-go/autosurvey"

	"stash.kopano.io/kgol/smtpst/internal/ipc"
	"stash.kopano.io/kgol/smtpst/server"
	"stash.kopano.io/kgol/smtpst/version"
)

func commandServe() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve [...args]",
		Short: "Start service",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				var exitCodeErr *ErrorWithExitCode
				if errors.As(err, &exitCodeErr) {
					os.Exit(exitCodeErr.Code)
				} else {
					os.Exit(1)
				}
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
	serveCmd.Flags().BoolVar(&defaultWithPprof, "with-pprof", defaultWithPprof, "With pprof enabled")
	serveCmd.Flags().StringVar(&defaultPprofListenAddr, "pprof-listen", defaultPprofListenAddr, "TCP listen address for pprof")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	bs := &bootstrap{}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		bs.Wait()
	}()

	err := bs.configure(ctx, cmd, args)
	if err != nil {
		return StartupError(err)
	}

	return bs.srv.Serve(ctx)
}

type bootstrap struct {
	sync.WaitGroup

	logger logrus.FieldLogger

	srv *server.Server
}

func (bs *bootstrap) configure(ctx context.Context, cmd *cobra.Command, args []string) error {
	if err := applyFlagsFromEnvFile(cmd, nil); err != nil {
		return err
	}

	logger, err := newLogger(!defaultLogTimestamp, defaultLogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	bs.logger = logger

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

	var withStatus bool

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
		OnStatus: func(srv *server.Server) {
			if !withStatus {
				bs.Add(1)
				go func() {
					<-ctx.Done()
					statusErr := clearStatus()
					if statusErr != nil {
						logger.WithError(statusErr).Errorln("failed to clear status")
					}
				}()
			}

			onStatus(srv)
			withStatus = true
		},

		APIBaseURI: apiBaseURL,

		DAgentListenAddress: defaultDAgentListenAddr,

		SMTPLocalAddr: defaultSMTPLocalAddr,
	}

	cfg.StatePath, err = filepath.Abs(defaultStatePath)
	if err != nil {
		return fmt.Errorf("state-path invalid: %w", err)
	}

	ipc.MustInitializeStatusSHM(cfg.StatePath, "")

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

	bs.srv, err = server.NewServer(cfg)
	if err != nil {
		return err
	}

	// Profiling support.
	withPprof, _ := cmd.Flags().GetBool("with-pprof")
	pprofListenAddr, _ := cmd.Flags().GetString("pprof-listen")
	if withPprof && pprofListenAddr != "" {
		runtime.SetMutexProfileFraction(5)
		go func() {
			pprofListen := pprofListenAddr
			logger.WithField("listenAddr", pprofListen).Infoln("pprof enabled, starting listener")
			if listenErr := http.ListenAndServe(pprofListen, nil); listenErr != nil {
				logger.WithError(listenErr).Errorln("unable to start pprof listener")
			}
		}()
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

	defer func() {
		if withStatus {
			statusErr := clearStatus()
			if statusErr != nil {
				logger.WithError(statusErr).Errorln("failed to clear status")
			}
		}
	}()

	return nil
}
