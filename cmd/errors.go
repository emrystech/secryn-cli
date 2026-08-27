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
	Code       int
	ErrorCode  string
	HTTPStatus int
	Message    string
	Cause      error
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
	return &CLIError{Code: exitUsage, ErrorCode: "validation_error", Message: msg}
}

func internalError(msg string, err error) error {
	return &CLIError{Code: exitGeneric, ErrorCode: "internal_error", Message: msg, Cause: err}
}

func mapAPIError(err error) error {
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return &CLIError{Code: exitGeneric, ErrorCode: "network_error", Message: err.Error(), Cause: err}
	}

	suffix := ""
	if apiErr.Message != "" {
		suffix = fmt.Sprintf(": %s", apiErr.Message)
	}

	switch apiErr.StatusCode {
	case http.StatusUnauthorized:
		return &CLIError{Code: exitAuth, ErrorCode: "authentication_failed", HTTPStatus: apiErr.StatusCode, Message: "Authentication failed (401). Update access key via `secryn config set --access-key ...` or SECRYN_ACCESS_KEY." + suffix, Cause: err}
	case http.StatusForbidden:
		return &CLIError{Code: exitAuth, ErrorCode: "access_denied", HTTPStatus: apiErr.StatusCode, Message: "Access denied (403). Confirm vault permissions for this access key." + suffix, Cause: err}
	case http.StatusNotFound:
		return &CLIError{Code: exitNotFound, ErrorCode: "not_found", HTTPStatus: apiErr.StatusCode, Message: "Resource not found (404). Check vault id, resource id, or name." + suffix, Cause: err}
	case http.StatusGone:
		return &CLIError{Code: exitNotFound, ErrorCode: "gone", HTTPStatus: apiErr.StatusCode, Message: "Resource no longer available (410). It may have been deleted or rotated." + suffix, Cause: err}
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return &CLIError{Code: exitUsage, ErrorCode: "api_validation_error", HTTPStatus: apiErr.StatusCode, Message: fmt.Sprintf("API request is invalid (%d)%s", apiErr.StatusCode, suffix), Cause: err}
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &CLIError{Code: exitGeneric, ErrorCode: "server_error", HTTPStatus: apiErr.StatusCode, Message: fmt.Sprintf("API server error (%d)%s", apiErr.StatusCode, suffix), Cause: err}
	default:
		return &CLIError{Code: exitGeneric, ErrorCode: "api_error", HTTPStatus: apiErr.StatusCode, Message: fmt.Sprintf("API request failed (%d)%s", apiErr.StatusCode, suffix), Cause: err}
	}
}

type jsonErrorResponse struct {
	OK    bool      `json:"ok"`
	Error jsonError `json:"error"`
}

type jsonError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status"`
}
