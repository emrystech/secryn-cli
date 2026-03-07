package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/secryn/secryn-cli/internal/client"
)

const (
	exitOK       = 0
	exitGeneric  = 1
	exitUsage    = 2
	exitAuth     = 3
	exitNotFound = 4
)

// CLIError carries an exit code and user-facing message.
type CLIError struct {
	Code    int
	Message string
	Cause   error
}

func (e *CLIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "command failed"
}

func usageError(msg string) error {
	return &CLIError{Code: exitUsage, Message: msg}
}

func internalError(msg string, err error) error {
	return &CLIError{Code: exitGeneric, Message: msg, Cause: err}
}

func mapAPIError(err error) error {
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return &CLIError{Code: exitGeneric, Message: err.Error(), Cause: err}
	}

	suffix := ""
	if apiErr.Message != "" {
		suffix = fmt.Sprintf(": %s", apiErr.Message)
	}

	switch apiErr.StatusCode {
	case http.StatusUnauthorized:
		return &CLIError{Code: exitAuth, Message: "Authentication failed (401). Update access key via `secryn config set --access-key ...` or SECRYN_ACCESS_KEY." + suffix, Cause: err}
	case http.StatusForbidden:
		return &CLIError{Code: exitAuth, Message: "Access denied (403). Confirm vault permissions for this access key." + suffix, Cause: err}
	case http.StatusNotFound:
		return &CLIError{Code: exitNotFound, Message: "Resource not found (404). Check vault id, resource id, or name." + suffix, Cause: err}
	case http.StatusGone:
		return &CLIError{Code: exitNotFound, Message: "Resource no longer available (410). It may have been deleted or rotated." + suffix, Cause: err}
	default:
		return &CLIError{Code: exitGeneric, Message: fmt.Sprintf("API request failed (%d)%s", apiErr.StatusCode, suffix), Cause: err}
	}
}
