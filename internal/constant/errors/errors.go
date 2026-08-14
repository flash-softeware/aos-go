package errors

import (
	"errors"
	"net/http"
)

type ErrorType string

const (
	ErrorTypeValidation   ErrorType = "validation"
	ErrorTypeNotFound     ErrorType = "not_found"
	ErrorTypeConflict     ErrorType = "conflict"
	ErrorTypeUnauthorized ErrorType = "unauthorized"
	ErrorTypeForbidden    ErrorType = "forbidden"
	ErrorTypeInternal     ErrorType = "internal"
	ErrorTypeUnknown      ErrorType = "unknown"
)

var (
	ErrUnexpected          = errors.New("unexpected error. please try again")
	ErrInternalServerError = errors.New("something went wrong. please try again later")
	ErrBadRequest          = errors.New("bad request")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrForbidden           = errors.New("forbidden")
	ErrNotFound            = errors.New("not found")

	ErrEmailAlreadyExists   = errors.New("this email address is already registered")
	ErrInvalidCredentials   = errors.New("invalid email or password")
)

var ErrorMap = map[error]int{
	ErrUnexpected:          http.StatusInternalServerError,
	ErrInternalServerError: http.StatusInternalServerError,
	ErrBadRequest:          http.StatusBadRequest,
	ErrUnauthorized:        http.StatusUnauthorized,
	ErrForbidden:           http.StatusForbidden,
	ErrNotFound:            http.StatusNotFound,

	ErrEmailAlreadyExists: http.StatusConflict,
	ErrInvalidCredentials: http.StatusUnauthorized,
	
}

var ErrorTypeMap = map[error]ErrorType{
	ErrUnexpected:          ErrorTypeInternal,
	ErrInternalServerError: ErrorTypeInternal,
	ErrBadRequest:          ErrorTypeValidation,
	ErrUnauthorized:        ErrorTypeUnauthorized,
	ErrForbidden:           ErrorTypeForbidden,
	ErrNotFound:            ErrorTypeNotFound,

	ErrEmailAlreadyExists: ErrorTypeConflict,
	ErrInvalidCredentials: ErrorTypeUnauthorized,
}
