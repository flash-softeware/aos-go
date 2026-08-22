package organization

import (
	"context"
	"encoding/json"
	"time"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/module/auth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/session"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

type Module struct {
	store  storage.Storage
	orgCfg auth.OrganizationOptions
}

func New(store storage.Storage, orgCfg auth.OrganizationOptions) *Module {
	return &Module{store: store, orgCfg: orgCfg}
}

func (m *Module) Enabled() bool {
	return m.orgCfg.Enabled
}

type CreateInput struct {
	Name string
}

type InviteResult struct {
	InviteToken string `json:"invite_token"`
	Email       string `json:"email"`
}

func (m *Module) Create(ctx context.Context, userID, sessionToken string, in CreateInput) (string, error) {
	if !m.orgCfg.Enabled {
		return "", aoserrors.ErrOrganizationsDisabled
	}
	if userID == "" {
		return "", aoserrors.ErrUserIDRequired
	}
	if in.Name == "" {
		return "", aoserrors.ErrNameRequired
	}

	orgBusinessID := uuid.New().String()
	iamID := uuid.New().String()

	var parentID string
	if inst, err := m.store.Resources().GetByType(ctx, "INSTALLATION"); err == nil && inst != nil {
		parentID = inst.ID
	}

	if err := m.store.Resources().Create(ctx, &entities.Resource{
		ID:           iamID,
		ResourceType: "ORGANIZATION",
		ResourceID:   orgBusinessID,
		ParentID:     parentID,
		Name:         in.Name,
	}); err != nil {
		return "", err
	}

	membershipID := uuid.New().String()
	if err := m.store.Memberships().Create(ctx, &entities.Membership{
		ID:           membershipID,
		UserID:       userID,
		ResourceType: "ORGANIZATION",
		ResourceID:   orgBusinessID,
		Status:       "ACTIVE",
	}); err != nil {
		return "", err
	}

	ownerRole, err := m.store.Roles().GetSystemByName(ctx, "Owner")
	if err != nil {
		return "", err
	}
	if err := m.store.Memberships().AssignRole(ctx, membershipID, iamID, ownerRole.ID); err != nil {
		return "", err
	}

	if sessionToken != "" {
		_ = m.store.Sessions().SetActiveResource(ctx, session.HashToken(sessionToken), iamID)
	}

	return orgBusinessID, nil
}

func (m *Module) Update(ctx context.Context, orgID, name string) error {
	if !m.orgCfg.Enabled {
		return aoserrors.ErrOrganizationsDisabled
	}
	_ = orgID
	_ = name
	return aoserrors.ErrOrganizationUpdateNotSupported
}

func (m *Module) Delete(ctx context.Context, orgID string) error {
	if !m.orgCfg.Enabled {
		return aoserrors.ErrOrganizationsDisabled
	}
	resource, err := m.store.Resources().GetByBusinessID(ctx, "ORGANIZATION", orgID)
	if err != nil {
		return err
	}
	return m.store.Resources().Delete(ctx, resource.ID)
}

func (m *Module) Invite(ctx context.Context, tenantID, orgID, email, roleID string) (*InviteResult, error) {
	if !m.orgCfg.Enabled {
		return nil, aoserrors.ErrOrganizationsDisabled
	}
	_ = tenantID

	if _, err := m.store.Resources().GetByBusinessID(ctx, "ORGANIZATION", orgID); err != nil {
		return nil, err
	}

	var userID string
	user, err := m.store.Users().GetByEmail(ctx, email)
	if err == nil && user != nil {
		userID = user.ID
		isMember, err := m.store.Memberships().HasOnResource(ctx, userID, orgID)
		if err != nil {
			return nil, err
		}
		if isMember {
			return nil, aoserrors.ErrAlreadyMember
		}
	}

	if _, err := m.store.Invitations().GetPending(ctx, email, "ORGANIZATION", orgID); err == nil {
		return nil, aoserrors.ErrInvitationAlreadyExists
	}

	if userID == "" {
		userID = uuid.New().String()
		if err := m.store.Users().Create(ctx, &entities.User{
			ID:        userID,
			Email:     email,
			FirstName: "Invited",
			LastName:  "User",
			Status:    "PENDING",
		}); err != nil {
			return nil, err
		}
	}

	invitationID := uuid.New().String()
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if err := m.store.Invitations().Create(ctx, &entities.Invitation{
		ID:           invitationID,
		Email:        email,
		ResourceType: "ORGANIZATION",
		ResourceID:   orgID,
		RoleID:       roleID,
		Status:       "PENDING",
		ExpiresAt:    expiresAt.Unix(),
	}); err != nil {
		return nil, err
	}

	inviteToken := uuid.New().String() + uuid.New().String()
	meta, _ := json.Marshal(map[string]string{
		"org_id":        orgID,
		"email":         email,
		"role_id":       roleID,
		"invitation_id": invitationID,
		"resource_type": "ORGANIZATION",
	})
	if err := m.store.Tokens().Insert(ctx, userID, "INVITATION", inviteToken, meta, expiresAt); err != nil {
		return nil, err
	}

	return &InviteResult{InviteToken: inviteToken, Email: email}, nil
}

func (m *Module) AddMember(ctx context.Context, orgID, userID, roleID string) error {
	if !m.orgCfg.Enabled {
		return aoserrors.ErrOrganizationsDisabled
	}
	resource, err := m.store.Resources().GetByBusinessID(ctx, "ORGANIZATION", orgID)
	if err != nil {
		return err
	}

	membershipID := uuid.New().String()
	if err := m.store.Memberships().Create(ctx, &entities.Membership{
		ID:           membershipID,
		UserID:       userID,
		ResourceType: "ORGANIZATION",
		ResourceID:   orgID,
		Status:       "ACTIVE",
	}); err != nil {
		return err
	}

	if roleID != "" {
		return m.store.Memberships().AssignRole(ctx, membershipID, resource.ID, roleID)
	}
	return nil
}

func (m *Module) Activate(ctx context.Context, userID, sessionToken, orgBusinessID string) error {
	if !m.orgCfg.Enabled {
		return aoserrors.ErrOrganizationsDisabled
	}
	if userID == "" || orgBusinessID == "" {
		return aoserrors.ErrUserAndOrgIDRequired
	}

	ok, err := m.store.Memberships().HasOnResource(ctx, userID, orgBusinessID)
	if err != nil {
		return err
	}
	if !ok {
		return aoserrors.ErrNotMemberOfOrganization
	}

	res, err := m.store.Resources().GetByBusinessID(ctx, "ORGANIZATION", orgBusinessID)
	if err != nil {
		return err
	}
	return m.store.Sessions().SetActiveResource(ctx, session.HashToken(sessionToken), res.ID)
}

func (m *Module) RemoveMember(ctx context.Context, orgID, userID string) error {
	if !m.orgCfg.Enabled {
		return aoserrors.ErrOrganizationsDisabled
	}
	membership, err := m.store.Memberships().Get(ctx, userID, "ORGANIZATION", orgID)
	if err != nil {
		return err
	}
	return m.store.Memberships().Remove(ctx, membership.ID)
}
