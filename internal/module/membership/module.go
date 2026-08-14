package membership

import (
	"context"
	"fmt"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

type Module struct {
	store  storage.Repository
	events *events.Bus
}

func New(store storage.Repository, bus *events.Bus) *Module {
	return &Module{store: store, events: bus}
}

type AddInput struct {
	TenantID     string
	UserID       string
	ResourceType string
	ResourceID   string
}

func (m *Module) Add(ctx context.Context, in AddInput) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	exists, err := m.store.CheckExistingMembership(ctx, in.UserID, in.ResourceID)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("user already has membership on resource")
	}

	membershipID, err := m.store.InsertMembershipOnResource(ctx, tx, in.TenantID, in.UserID, in.ResourceType, in.ResourceID)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	if m.events != nil {
		_ = m.events.Emit(ctx, events.EventMembershipCreated, events.MembershipCreatedEvent{
			MembershipID: membershipID,
			UserID:       in.UserID,
			ResourceType: in.ResourceType,
			ResourceID:   in.ResourceID,
			TenantID:     in.TenantID,
		})
	}

	return membershipID, nil
}

func (m *Module) AssignRole(ctx context.Context, membershipID, iamResourceID, roleID string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.InsertRoleAssignment(ctx, tx, membershipID, iamResourceID, roleID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// Assign adds membership and assigns a role on the IAM resource in one transaction.
func (m *Module) Assign(ctx context.Context, in AddInput, iamResourceID, roleID string) (string, error) {
	membershipID, err := m.Add(ctx, in)
	if err != nil {
		return "", err
	}
	if err := m.AssignRole(ctx, membershipID, iamResourceID, roleID); err != nil {
		return "", err
	}
	if m.events != nil {
		_ = m.events.Emit(ctx, events.EventRoleAssigned, events.RoleAssignedEvent{
			MembershipID: membershipID,
			UserID:       in.UserID,
			RoleID:       roleID,
			ResourceID:   in.ResourceID,
		})
	}
	return membershipID, nil
}

func (m *Module) UserHasAccess(ctx context.Context, userID, resourceID string) (bool, error) {
	return m.store.UserHasResourceMembership(ctx, userID, resourceID)
}
