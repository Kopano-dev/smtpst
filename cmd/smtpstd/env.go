/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func applyFlagsFromEnvFile(cmd *cobra.Command, mapping map[string]string) error {
	if defaultEnvConfigFile != "" {
		envConfigFile, err := filepath.Abs(defaultEnvConfigFile)
		if err != nil {
			return fmt.Errorf("config flag value invalid: %w", err)
		}

		var envConfig map[string]string
		envConfig, err = godotenv.Read(envConfigFile)
		if err != nil {
			return fmt.Errorf("config read error: %w", err)
		}

		if mapping == nil {
			mapping = make(map[string]string)
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				if flag.Changed || flag.Name == "help" {
					// Ignore flags which are set already or are on black list.
					return
				}
				mapping[flag.Name] = "" // Add without value, will auto generate below.
			})
		}

		// Support setting values from config file if they are not set explicitly via flags.
		for flagName, envName := range mapping {
			if cmd.Flags().Changed(flagName) {
				continue
			}
			if envName == "" {
				// Auto generate, change all - to _ which is all in most of the cases.
				envName = strings.ReplaceAll(flagName, "-", "_")
			}
			if value, ok := envConfig[envName]; ok {
				if err = cmd.Flags().Set(flagName, value); err != nil {
					return fmt.Errorf("failed to apply %v config: %w", envName, err)
				}
			}
		}
	}

	return nil
}
