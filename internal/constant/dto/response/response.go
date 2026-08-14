package response

import (
	"encoding/json"
	"net/http"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type Response struct {
	Status  int            `json:"status,omitempty"`
	Message string         `json:"message,omitempty"`
	Data    any            `json:"data,omitempty"`
	Meta    any            `json:"meta,omitempty"`
	Error   *ErrorResponse `json:"error,omitempty"`
}

type Metadata struct {
	TotalDocs     int64  `json:"total_docs"`
	Limit         int64  `json:"limit"`
	TotalPages    int64  `json:"total_pages"`
	Page          int64  `json:"page"`
	PagingCounter int64  `json:"paging_counter"`
	HasPrevPage   bool   `json:"has_prev_page"`
	HasNextPage   bool   `json:"has_next_page"`
	PrevPage      *int64 `json:"prev_page,omitempty"`
	NextPage      *int64 `json:"next_page,omitempty"`
}
type ErrorResponse struct {
	Type    errors.ErrorType `json:"type"`
	Message string           `json:"message,omitempty"`
	Details []FieldError     `json:"details,omitempty"`
}

type FieldError struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func SendSuccessResponse(w http.ResponseWriter, statusCode int, message string, data, meta any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(Response{
		Status:  statusCode,
		Message: message,
		Data:    data,
		Meta:    meta,
	}); err != nil {
		w.WriteHeader(errors.ErrorMap[errors.ErrUnexpected])
		json.NewEncoder(w).Encode(Response{
			Status: errors.ErrorMap[errors.ErrUnexpected],
			Error: &ErrorResponse{
				Type:    errors.ErrorTypeUnknown,
				Message: errors.ErrUnexpected.Error(),
			},
		})
		return
	}
}

func SendErrorResponse(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")

	if ve, ok := err.(validation.Errors); ok {
		fieldErr := ErrorFields(ve)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Status: http.StatusBadRequest,
			Error: &ErrorResponse{
				Type:    errors.ErrorTypeValidation,
				Message: "invalid input data",
				Details: fieldErr,
			},
		})
		return
	}

	statusCode, ok := errors.ErrorMap[err]
	if !ok {
		message := err.Error()
		statusCode = http.StatusBadRequest
		errType := errors.ErrorTypeValidation
		if message == "" {
			statusCode = errors.ErrorMap[errors.ErrUnexpected]
			message = errors.ErrUnexpected.Error()
			errType = errors.ErrorTypeUnknown
		}

		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(Response{
			Status: statusCode,
			Error: &ErrorResponse{
				Type:    errType,
				Message: message,
			},
		})
		return
	}

	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(Response{
		Status: statusCode,
		Error: &ErrorResponse{
			Type:    errors.ErrorTypeMap[err],
			Message: err.Error(),
		},
	}); err != nil {
		w.WriteHeader(errors.ErrorMap[errors.ErrUnexpected])
		json.NewEncoder(w).Encode(Response{
			Status: errors.ErrorMap[errors.ErrUnexpected],
			Error: &ErrorResponse{
				Type:    errors.ErrorTypeUnknown,
				Message: errors.ErrUnexpected.Error(),
			},
		})
	}
}

func ErrorFields(err error) []FieldError {
	var errs []FieldError

	if data, ok := err.(validation.Errors); ok {
		for i, v := range data {
			nestedErrors := ErrorFields(v)
			if len(nestedErrors) > 0 {
				errs = append(errs, nestedErrors...)
			} else {
				errs = append(errs, FieldError{
					Title:       i,
					Description: v.Error(),
				})
			}
		}

		return errs
	}

	return nil
}
