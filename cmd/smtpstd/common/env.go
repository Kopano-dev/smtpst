/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	DefaultEnvConfigFile = os.Getenv("SMTPSTD_DEFAULT_ENV_CONFIG")
)

func ApplyFlagsFromEnvFile(cmd *cobra.Command, mapping map[string]string) error {
	if DefaultEnvConfigFile != "" {
		envConfigFile, err := filepath.Abs(DefaultEnvConfigFile)
		if err != nil {
			return fmt.Errorf("invalid config path: %w", err)
		}

		var envConfig map[string]string
		envConfig, err = godotenv.Read(strings.Split(envConfigFile, ":")...)
		if err != nil {
			return fmt.Errorf("config read error: %w", err)
		}

		if mapping == nil {
			mapping = make(map[string]string)
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				if flag.Changed || flag.Name == "help" || flag.Name == "config" {
					// Ignore flags which are set already or are on black list.
					return
				}
				mapping[flag.Name] = "" // Add without value, will auto generate below.
			})
		}

		// Support setting values from config file if they are not set explicitly via flags.
		for flagName, envName := range mapping {
			flag := cmd.Flags().Lookup(flagName)

			if flag.Changed {
				continue
			}

			// Get value.
			value := flag.Value
			// Check if its a slice.
			sliceValue, isSlice := value.(pflag.SliceValue)

			// Auto generate env name from flag name if not set.
			if envName == "" {
				// Change all - to _ which is all in most of the cases.
				envName = strings.ReplaceAll(flagName, "-", "_")
				if isSlice {
					// Add an "s" to the end of the envName if its a slice.
					envName += "s"
				}
			}
			if v, ok := envConfig[envName]; ok {
				if isSlice {
					err = sliceValue.Replace(strings.Split(v, " "))
				} else {
					err = flag.Value.Set(v)
				}
				if err != nil {
					return fmt.Errorf("failed to apply %v config: %w", envName, err)
				}
			}
		}
	}

	return nil
}
