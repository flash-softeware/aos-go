package resources

import (
	"context"

	"github.com/aos/sdk-go/internal/storage"
)

type Module struct {
	store storage.Repository
}

func New(store storage.Repository) *Module {
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
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	parentIAMID := ""
	if in.ParentResource != "" && in.ParentType != "" {
		parentIAMID, err = m.store.GetIAMResource(ctx, tx, in.ParentResource, in.ParentType)
		if err != nil {
			return "", err
		}
	}

	iamID, err := m.store.InsertIAMResource(ctx, tx, in.TenantID, in.Type, in.ResourceID, parentIAMID, in.Name)
	if err != nil {
		return "", err
	}

	return iamID, tx.Commit(ctx)
}

func (m *Module) IAMResourceID(ctx context.Context, resourceID, resourceType string) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	return m.store.GetIAMResource(ctx, tx, resourceID, resourceType)
}
