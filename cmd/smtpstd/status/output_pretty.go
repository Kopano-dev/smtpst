/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package status

import (
	"fmt"
	"io"
	"text/template"

	"github.com/muesli/termenv"

	"stash.kopano.io/kgol/smtpst/server"
)

const prettyTemplate = `
{{- WithConnectedForground (Bold "provider")}}: {{WithConnectedForground (or .HTTPProviderURL "not set")}}
  {{Bold "connected"}}: {{.HTTPConnected}}
  {{Bold "licenses"}}:
    {{- if .HTTPLicenseLIDs}}{{- range .HTTPLicenseLIDs}}
    - {{.}}
    {{- end}}
    {{- else}}
    - none
    {{- end}}

{{if .SessionID}}{{WithSessionColor (Bold "session")}}: {{WithSessionColor (printf .SessionID)}}
  {{Bold "expiration"}}: {{.Expiration}}
  {{Bold "domains"}}:
    {{- range .Domains}}
    - {{.}}
    {{- end}}
{{- end}}
`

func templateFuncs(p termenv.Profile, status *server.Status) template.FuncMap {
	// Define some colors.
	okColor := p.Color("112")
	nokColor := p.Color("196")
	sessionColor := p.Color("214")

	// Subset of the helpers in termenv, so we have better control and can turn
	// of all formatting of the terminal supports ASCII only.
	return template.FuncMap{
		"Bold": func(values ...interface{}) string {
			if p == termenv.Ascii {
				// Do not do any bold, if terminal only supports ASCII.
				return values[0].(string)
			}
			s := termenv.String(values[0].(string))
			return s.Bold().String()
		},
		"WithConnectedForground": func(values ...interface{}) string {
			s := termenv.String(fmt.Sprintf("%v", values[len(values)-1]))
			if status.HTTPConnected {
				s = s.Foreground(okColor)
			} else {
				s = s.Foreground(nokColor)
			}
			return s.String()
		},
		"WithSessionColor": func(values ...interface{}) string {
			s := termenv.String(fmt.Sprintf("%v", values[len(values)-1])).Foreground(sessionColor)
			return s.String()
		},
	}
}

func outputPretty(w io.Writer, status *server.Status) error {
	// Load helpers and template.
	f := templateFuncs(termenv.ColorProfile(), status)
	tpl, err := template.New("tpl").Funcs(f).Parse(prettyTemplate)
	if err != nil {
		panic(err)
	}

	// Render.
	return tpl.Execute(w, status)
}
