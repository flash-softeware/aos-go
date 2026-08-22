package permissions

import (
	"context"
	"strings"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

// Module manages the global permission catalog. Permission codes are never org-scoped;
// organization context is enforced on roles and role assignments when organizations are enabled.
type Module struct {
	store       storage.Storage
	orgsEnabled bool
}

func New(store storage.Storage, orgsEnabled bool) *Module {
	return &Module{store: store, orgsEnabled: orgsEnabled}
}

func (m *Module) OrganizationsEnabled() bool {
	return m.orgsEnabled
}

type RegisterInput struct {
	Code         string
	Description  string
	ResourceType string
	Action       string
}

func (m *Module) Register(ctx context.Context, in RegisterInput) (string, error) {
	resourceType := in.ResourceType
	action := in.Action
	if resourceType == "" || action == "" {
		resourceType, action = splitCode(in.Code)
	}

	permID := uuid.New().String()
	err := m.store.Permissions().Create(ctx, &entities.Permission{
		ID:           permID,
		Code:         in.Code,
		Description:  in.Description,
		ResourceType: resourceType,
		Action:       action,
	})
	return permID, err
}

func (m *Module) RegisterMany(ctx context.Context, codes ...string) error {
	for _, code := range codes {
		if _, err := m.Register(ctx, RegisterInput{Code: code, Description: "Permission " + code}); err != nil {
			return err
		}
	}
	return nil
}

func splitCode(code string) (resourceType, action string) {
	if code == "*" {
		return "*", "*"
	}
	parts := strings.SplitN(code, ".", 2)
	if len(parts) == 1 {
		return parts[0], "*"
	}
	return parts[0], parts[1]
}
