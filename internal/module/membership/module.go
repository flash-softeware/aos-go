package membership

import (
	"context"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

type Module struct {
	store  storage.Storage
	events *events.Bus
}

func New(store storage.Storage, bus *events.Bus) *Module {
	return &Module{store: store, events: bus}
}

type AddInput struct {
	TenantID     string
	UserID       string
	ResourceType string
	ResourceID   string
}

func (m *Module) Add(ctx context.Context, in AddInput) (string, error) {
	_ = in.TenantID

	ok, err := m.store.Memberships().HasOnResource(ctx, in.UserID, in.ResourceID)
	if err != nil {
		return "", err
	}
	if ok {
		return "", aoserrors.ErrMembershipAlreadyOnResource
	}

	membershipID := uuid.New().String()
	err = m.store.Memberships().Create(ctx, &entities.Membership{
		ID:           membershipID,
		UserID:       in.UserID,
		ResourceType: in.ResourceType,
		ResourceID:   in.ResourceID,
		Status:       "ACTIVE",
	})
	if err != nil {
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
	return m.store.Memberships().AssignRole(ctx, membershipID, iamResourceID, roleID)
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
	return m.store.Memberships().HasOnResource(ctx, userID, resourceID)
}
