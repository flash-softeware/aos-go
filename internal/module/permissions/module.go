package permissions

import (
	"context"
	"strings"

	"github.com/aos/sdk-go/internal/storage"
)

type Module struct {
	store storage.Repository
}

func New(store storage.Repository) *Module {
	return &Module{store: store}
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

	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	permID, err := m.store.InsertPermission(ctx, tx, resourceType, action, in.Code, in.Description)
	if err != nil {
		return "", err
	}
	return permID, tx.Commit(ctx)
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
