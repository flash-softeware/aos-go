package iam

import (
	"encoding/json"
	"net/http"

	dto "github.com/aos/sdk-go/internal/constant/dto/request"
	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/constant/errors"
	"github.com/aos/sdk-go/internal/module/iam"
)

type IamHandler struct {
	iamEngine *iam.Engine
}

func NewIamHandler(iamEngine *iam.Engine) *IamHandler {
	return &IamHandler{iamEngine: iamEngine}
}

func (h *IamHandler) CheckPermission(w http.ResponseWriter, r *http.Request) {
	var req dto.IAMCanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	params := iam.CanParams{
		UserID:     req.UserID,
		ResourceID: req.ResourceID,
		Permission: req.Permission,
		TenantID:   req.TenantID,
	}

	allowed, err := h.iamEngine.Can(r.Context(), params)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "Permission checked", map[string]bool{"allowed": allowed}, nil)
}
