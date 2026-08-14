package organization

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

type Module struct {
	store storage.Repository
}

func New(store storage.Repository) *Module {
	return &Module{store: store}
}

type CreateInput struct {
	Name string
}

type InviteResult struct {
	InviteToken string `json:"invite_token"`
	Email       string `json:"email"`
}

func (m *Module) Create(ctx context.Context, tenantID, userID string, in CreateInput) (string, error) {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	slug := strings.ToLower(strings.ReplaceAll(in.Name, " ", "-"))
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "organization"
	}
	slug = slug + "-" + uuid.New().String()[:8]

	orgID, err := m.store.InsertOrganization(ctx, tx, tenantID, in.Name, slug)
	if err != nil {
		return "", err
	}

	if err := m.store.InsertOrgResource(ctx, tx, tenantID, orgID); err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	return orgID, nil
}

func (m *Module) Update(ctx context.Context, orgID, name string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.UpdateOrganization(ctx, tx, orgID, name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *Module) Delete(ctx context.Context, orgID string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.DeleteOrganization(ctx, tx, orgID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *Module) Invite(ctx context.Context, tenantID, orgID, email, roleID string) (*InviteResult, error) {
	userID, err := m.store.GetUserIDByEmail(ctx, email)
	if err == nil && userID != "" {
		isMember, err := m.store.CheckExistingMembership(ctx, userID, orgID)
		if err != nil {
			return nil, err
		}
		if isMember {
			return nil, errors.New("409 already member")
		}
	}

	pending, err := m.store.CheckPendingInvitation(ctx, email, orgID)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, errors.New("invitation already exists")
	}

	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if userID == "" {
		userID, err = m.store.InsertUserWithStatus(ctx, tx, email, "Invited", "User", "PENDING")
		if err != nil {
			return nil, err
		}
	}

	if err := m.store.InsertPendingOrganizationMember(ctx, tx, tenantID, orgID, userID, roleID); err != nil {
		return nil, err
	}

	if _, err := m.store.InsertInvitation(ctx, tx, tenantID, email, "ORGANIZATION", orgID, roleID); err != nil {
		return nil, err
	}

	inviteToken := uuid.New().String() + uuid.New().String()
	meta, _ := json.Marshal(map[string]string{"org_id": orgID, "email": email})
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if err := m.store.InsertUserTokenTx(ctx, tx, userID, "INVITATION", inviteToken, meta, expiresAt); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &InviteResult{InviteToken: inviteToken, Email: email}, nil
}

func (m *Module) AddMember(ctx context.Context, orgID, userID, roleID string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.InsertOrganizationMember(ctx, tx, orgID, userID, roleID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *Module) RemoveMember(ctx context.Context, orgID, userID string) error {
	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := m.store.DeleteOrganizationMember(ctx, tx, orgID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
