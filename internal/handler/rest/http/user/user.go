package user

import (
	"encoding/json"
	"net/http"

	dto "github.com/aos/sdk-go/internal/constant/dto/request"
	"github.com/aos/sdk-go/internal/constant/dto/response"
	"github.com/aos/sdk-go/internal/constant/errors"
	"github.com/aos/sdk-go/internal/module/user"
)

type UserHandler struct {
	userModule *user.Module
}

func NewUserHandler(userModule *user.Module) *UserHandler {
	return &UserHandler{userModule: userModule}
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.SendErrorResponse(w, errors.ErrBadRequest)
		return
	}

	in := user.RegisterInput{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}
	out, err := h.userModule.Register(r.Context(), req.TenantID, in)
	if err != nil {
		response.SendErrorResponse(w, err)
		return
	}
	response.SendSuccessResponse(w, http.StatusOK, "User registered", out, nil)
}
