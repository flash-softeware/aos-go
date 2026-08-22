package resources

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

type Module struct {
	store storage.Storage
}

func New(store storage.Storage) *Module {
	return &Module{store: store}
}

type CreateInput struct {
	TenantID       string
	Type           string
	ResourceID     string
	ParentResource string // business resource_id of parent
	ParentType     string // e.g. TENANT, ORGANIZATION
	Name           string
}

func (m *Module) Create(ctx context.Context, in CreateInput) (string, error) {
	_ = in.TenantID

	parentIAMID := ""
	if in.ParentResource != "" && in.ParentType != "" {
		parent, err := m.store.Resources().GetByBusinessID(ctx, in.ParentType, in.ParentResource)
		if err != nil {
			return "", err
		}
		parentIAMID = parent.ID
	}

	businessID := in.ResourceID
	if businessID == "" {
		businessID = uuid.New().String()
	}

	iamID := uuid.New().String()
	err := m.store.Resources().Create(ctx, &entities.Resource{
		ID:           iamID,
		ResourceType: in.Type,
		ResourceID:   businessID,
		ParentID:     parentIAMID,
		Name:         in.Name,
	})
	if err != nil {
		return "", err
	}

	return iamID, nil
}

func (m *Module) IAMResourceID(ctx context.Context, resourceID, resourceType string) (string, error) {
	resource, err := m.store.Resources().GetByBusinessID(ctx, resourceType, resourceID)
	if err != nil {
		return "", err
	}
	return resource.ID, nil
}
