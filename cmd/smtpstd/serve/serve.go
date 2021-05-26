/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package serve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Include pprof for debugging, its only enabled when --with-pprof is given.
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

	"stash.kopano.io/kgol/smtpst/cmd/smtpstd/common"
	"stash.kopano.io/kgol/smtpst/internal/ipc"
	"stash.kopano.io/kgol/smtpst/server"
	"stash.kopano.io/kgol/smtpst/version"
)

// Default param values used by this command.
var (
	DefaultLogTimestamp         = true
	DefaultLogLevel             = "info"
	DefaultSystemdNotify        = false
	DefaultProviderURL          = os.Getenv("SMTPSTD_DEFAULT_PROVIDER_URL")
	DefaultDomains              = []string{}
	DefaultPreferredDomainBases = []string{}
	DefaultDAgentListenAddr     = "127.0.0.1:10025"
	DefaultSMTPLocalAddr        = "127.0.0.1:25"
	DefaultStatePath            = os.Getenv("SMTPSTD_DEFAULT_STATE_PATH")
	DefaultLicensesPath         = "/etc/kopano/licenses"
	DefaultIss                  = os.Getenv("SMTPSTD_DEFAULT_OIDC_ISSUER_IDENTIFIER")
	DefaultWithPprof            = false
	DefaultPprofListenAddr      = "127.0.0.1:6060"
	DefaultPostmasterEmail      = "" // TODO(longsleep): Implement postmaster error reporting via email.
)

func init() {
	envDefaultDAgentListenAddr := os.Getenv("SMTPST_DEFAULT_DAGENT_LISTEN")
	if envDefaultDAgentListenAddr != "" {
		DefaultDAgentListenAddr = envDefaultDAgentListenAddr
	}

	envdefaultSMTPLocalAddr := os.Getenv("SMTPST_DEFAULT_SMTP_LOCAL")
	if envdefaultSMTPLocalAddr != "" {
		DefaultSMTPLocalAddr = envdefaultSMTPLocalAddr
	}

	envDefaultLicensesPath := os.Getenv("SMTPST_DEFAULT_LICENSES_PATH")
	if envDefaultLicensesPath != "" {
		DefaultLicensesPath = envDefaultLicensesPath
	}

	if DefaultStatePath == "" {
		DefaultStatePath, _ = os.Getwd()
	}
}

func CommandServe() *cobra.Command {
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

	serveCmd.Flags().BoolVar(&DefaultLogTimestamp, "log-timestamp", DefaultLogTimestamp, "Prefix each log line with timestamp")
	serveCmd.Flags().StringVar(&DefaultLogLevel, "log-level", DefaultLogLevel, "Log level (one of panic, fatal, error, warn, info or debug)")
	serveCmd.Flags().BoolVar(&DefaultSystemdNotify, "systemd-notify", DefaultSystemdNotify, "Enable systemd sd_notify callback")
	serveCmd.Flags().StringVar(&DefaultProviderURL, "provider-url", DefaultProviderURL, "URL to the SMTP secure transport provider API")
	serveCmd.Flags().StringArrayVar(&DefaultDomains, "domain", DefaultDomains, "Domain to receive for")
	serveCmd.Flags().StringArrayVar(&DefaultPreferredDomainBases, "preferred-base", DefaultPreferredDomainBases, "The preferred domain base, multiple allowed")
	serveCmd.Flags().StringVar(&DefaultDAgentListenAddr, "dagent-listen", DefaultDAgentListenAddr, "TCP listen address for SMTP delivery agent")
	serveCmd.Flags().StringVar(&DefaultSMTPLocalAddr, "smtp-local", DefaultSMTPLocalAddr, "TCP address for local SMTP")
	serveCmd.Flags().StringVar(&DefaultStatePath, "state-path", DefaultStatePath, "Full path to writable state directory")
	serveCmd.Flags().StringVar(&DefaultLicensesPath, "licenses-path", DefaultLicensesPath, "Path to the folder containing Kopano license files")
	serveCmd.Flags().StringVar(&DefaultIss, "iss", DefaultIss, "OIDC issuer URL")
	serveCmd.Flags().BoolVar(&DefaultWithPprof, "with-pprof", DefaultWithPprof, "With pprof enabled")
	serveCmd.Flags().StringVar(&DefaultPprofListenAddr, "pprof-listen", DefaultPprofListenAddr, "TCP listen address for pprof")

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
	if err := common.ApplyFlagsFromEnvFile(cmd, nil); err != nil {
		return err
	}

	logger, err := newLogger(!DefaultLogTimestamp, DefaultLogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	bs.logger = logger

	logger.Debugln("serve start")

	apiBaseURL, err := url.Parse(DefaultProviderURL)
	if err != nil {
		return fmt.Errorf("invalid provider-url: %w", err)
	}
	if apiBaseURL.Host == "" {
		return fmt.Errorf("provider-url must not be empty")
	}

	if DefaultStatePath == "" {
		return fmt.Errorf("state-path must not be empty")
	}
	if info, statErr := os.Stat(DefaultStatePath); statErr != nil || !info.IsDir() {
		return fmt.Errorf("state-path error or not a directory: %w", statErr)
	}

	issURL, err := url.Parse(DefaultIss)
	if err != nil {
		return fmt.Errorf("invalid iss: %w", err)
	}

	var withStatus bool

	cfg := &server.Config{
		Iss: issURL,

		Logger: logger,

		OnReady: func(srv *server.Server) {
			if DefaultSystemdNotify {
				ok, notifyErr := systemDaemon.SdNotify(false, systemDaemon.SdNotifyReady)
				logger.WithField("ok", ok).Debugln("called systemd sd_notify ready")
				if notifyErr != nil {
					logger.WithError(notifyErr).Errorln("failed to trigger systemd sd_notify")
				}
			}
		},
		OnStatus: func(srv *server.Server) {
			if !withStatus {
				withStatus = true
				bs.Add(1)
				go func() {
					defer bs.Done()
					<-ctx.Done()
					statusErr := clearStatus()
					if statusErr != nil {
						logger.WithError(statusErr).Errorln("failed to clear status")
					}
				}()
			}

			onStatus(srv)
		},

		APIBaseURI: apiBaseURL,

		DAgentListenAddress: DefaultDAgentListenAddr,

		SMTPLocalAddr: DefaultSMTPLocalAddr,

		PreferredDomainBases: DefaultPreferredDomainBases,
	}

	cfg.StatePath, err = filepath.Abs(DefaultStatePath)
	if err != nil {
		return fmt.Errorf("state-path invalid: %w", err)
	}

	ipc.MustInitializeStatusSHM(cfg.StatePath, "")

	cfg.LicensesPath, err = filepath.Abs(DefaultLicensesPath)
	if err != nil {
		return fmt.Errorf("licenses-path invalid: %w", err)
	}

	for _, domain := range DefaultDomains {
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

	return nil
}
