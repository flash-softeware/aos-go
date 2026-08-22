package authz

import (
	"encoding/json"
	"net/http"

	dto "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/request"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/iam"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
)

type Handler struct {
	iam *iam.Engine
}

func NewHandler(iamEngine *iam.Engine) *Handler {
	return &Handler{iam: iamEngine}
}

func (h *Handler) Can(w http.ResponseWriter, r *http.Request) {
	sess := identity.SessionFromRequest(r)
	if sess.UserID == "" {
		response.SendErrorResponse(w, errors.ErrUnauthorized)
		return
	}

	var req dto.MeCanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Permission == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	resourceID := req.ResourceID
	if resourceID == "" {
		resourceID = identity.ActiveResourceIAMIDFromContext(r.Context())
	}
	if resourceID == "" {
		resourceID = sess.OrgID
	}
	if resourceID == "" {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	allowed, err := h.iam.Can(r.Context(), iam.CanParams{
		UserID:     sess.UserID,
		ResourceID: resourceID,
		Permission: req.Permission,
		TenantID:   sess.TenantID,
	})
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}

	response.SendSuccessResponse(w, http.StatusOK, "Authorization evaluated", map[string]bool{
		"allowed": allowed,
	}, nil)
}
