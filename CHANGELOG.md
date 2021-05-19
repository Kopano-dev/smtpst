# CHANGELOG

## Unreleased



## v0.3.0 (2021-05-19)

- Improve error detail for response errors in session API
- Log license ids used for session authentication
- Always pass configured domains to server if any
- Add support for perferred base config


## v0.2.1 (2021-04-19)

- Always write updated status
- Add clean exit deadline


## v0.2.0 (2021-04-16)

- Handle license add/remove/change correctly
- Add channel broadcaster utility
- Add atomic comparison setters
- Split up utils
- Send service to sleep without credentials
- Add active license ids to status output
- Get deadlock race condition on startup
- Improve status pretty print resilience
- Add missing check when resetting domains claims


## v0.1.0 (2021-04-15)

- Actually set default values via bin script
- Add shell autocompletion generator
- Add man page generator sub command
- Refactor sub commands into sub folders
- Implement proper automatic restart and exit code control
- Add pprof support
- Log domains claims update only if really something changed
- Allow to set all built in defaults via env
- Improve locking code
- Support to load multiple env config files
- Include response message in refresh error message
- Use misspelled license file of external godotenv dependency
- Load config file automatically for status command
- Properly trigger OnStatus whenever required
- Support to load config file
- Use default EXC path consistent to other Kopano services
- Improve and reduce log verbosity
- Bring back call to OnReady hook
- Implement status subcommand
- Log applied domains claims in info level
- Send along extra licenses with connect requests
- Use smtpst product license if any
- Add bin script, configuration and systemd service files
- Update go license ranger to compatible version
- Improve HTTP and SMTP client configuration
- Improve client side session terminate logging
- Load and use Kopano licenses on startup
- Create x509 certificate and add it to http client
- Don't try to save nil domains claims

