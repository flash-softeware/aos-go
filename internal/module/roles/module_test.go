package roles_test

import (
	"context"
	"errors"
	"testing"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/roles"
)

func TestCreateRequiresOrganizationWhenEnabled(t *testing.T) {
	m := roles.New(nil, true)
	_, err := m.Create(context.Background(), roles.CreateInput{Name: "Cashier"})
	if !errors.Is(err, aoserrors.ErrOrganizationIDRequired) {
		t.Fatalf("expected ErrOrganizationIDRequired, got %v", err)
	}
}

func TestCreateRejectsOrganizationWhenDisabled(t *testing.T) {
	m := roles.New(nil, false)
	_, err := m.Create(context.Background(), roles.CreateInput{
		Name:                   "Admin",
		OrganizationBusinessID: "org-uuid",
	})
	if !errors.Is(err, aoserrors.ErrOrganizationScopeNotAllowed) {
		t.Fatalf("expected ErrOrganizationScopeNotAllowed, got %v", err)
	}
}

func TestCreateRejectsSystemRoleWhenOrgsEnabled(t *testing.T) {
	m := roles.New(nil, true)
	_, err := m.Create(context.Background(), roles.CreateInput{
		Name:                   "Owner",
		IsSystem:               true,
		OrganizationBusinessID: "org-uuid",
	})
	if err == nil {
		t.Fatal("expected error creating system role when orgs enabled")
	}
}
