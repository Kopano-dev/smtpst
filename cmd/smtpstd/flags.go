/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package main

import (
	"os"
)

var (
	defaultLogTimestamp     = true
	defaultLogLevel         = "info"
	defaultSystemdNotify    = false
	defaultProviderURL      = os.Getenv("SMTPSTD_DEFAULT_PROVIDER_URL")
	defaultDomains          = []string{}
	defaultDAgentListenAddr = "127.0.0.1:10025"
	defaultSMTPLocalAddr    = "127.0.0.1:25"
	defaultStatePath        = os.Getenv("SMTPSTD_DEFAULT_STATE_PATH")
	defaultLicensesPath     = "/etc/kopano/licenses"
	defaultIss              = os.Getenv("SMTPSTD_DEFAULT_OIDC_ISSUER_IDENTIFIER")
	defaultEnvConfigFile    = os.Getenv("SMTPSTD_DEFAULT_ENV_CONFIG")
)

func init() {
	envDefaultDAgentListenAddr := os.Getenv("SMTPST_DEFAULT_DAGENT_LISTEN")
	if envDefaultDAgentListenAddr != "" {
		defaultDAgentListenAddr = envDefaultDAgentListenAddr
	}

	envdefaultSMTPLocalAddr := os.Getenv("SMTPST_DEFAULT_SMTP_LOCAL")
	if envdefaultSMTPLocalAddr != "" {
		defaultSMTPLocalAddr = envdefaultSMTPLocalAddr
	}

	envDefaultLicensesPath := os.Getenv("SMTPST_DEFAULT_LICENSES_PATH")
	if envDefaultLicensesPath != "" {
		defaultLicensesPath = envDefaultLicensesPath
	}
}
