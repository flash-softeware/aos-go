package auth

import (
	"context"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/session"
)

// OrganizationOptions configures org-layer behavior for auth and authorization scope.
type OrganizationOptions struct {
	Enabled              bool
	AutoSetActiveOnLogin bool
}

func (m *Module) OrganizationsEnabled() bool {
	return m.orgOpts.Enabled
}

func (m *Module) ResolveAuthorizationScopeIAMID(ctx context.Context, sess *Session) (string, error) {
	if !m.orgOpts.Enabled {
		return m.installationIAMID(ctx)
	}
	if sess == nil || sess.ActiveResourceIAMID == "" {
		return "", aoserrors.ErrNoActiveOrganization
	}
	return sess.ActiveResourceIAMID, nil
}

func (m *Module) installationIAMID(ctx context.Context) (string, error) {
	if m.cachedInstallationID != "" {
		return m.cachedInstallationID, nil
	}
	inst, err := m.store.Resources().GetByType(ctx, "INSTALLATION")
	if err != nil {
		return "", err
	}
	m.cachedInstallationID = inst.ID
	return inst.ID, nil
}

func (m *Module) enrichSession(ctx context.Context, s *entities.Session) (*Session, error) {
	out := &Session{
		UserID:              s.UserID,
		ActiveResourceIAMID: s.ActiveResourceID,
	}
	if s.ActiveResourceID == "" {
		return out, nil
	}

	res, err := m.store.Resources().GetByID(ctx, s.ActiveResourceID)
	if err != nil {
		return out, nil
	}
	if res.ResourceType == "ORGANIZATION" {
		out.ActiveOrganizationID = res.ResourceID
		out.OrgID = res.ResourceID
	}
	return out, nil
}

func (m *Module) setActiveResourceIAM(ctx context.Context, sessionToken, iamResourceID string) error {
	hash := session.HashToken(sessionToken)
	return m.store.Sessions().SetActiveResource(ctx, hash, iamResourceID)
}

func (m *Module) autoSetActiveOrganization(ctx context.Context, sessionToken, userID string) error {
	if !m.orgOpts.Enabled || !m.orgOpts.AutoSetActiveOnLogin {
		return nil
	}

	memberships, err := m.store.Memberships().ListByUser(ctx, userID)
	if err != nil {
		return err
	}

	var orgMemberships []*entities.Membership
	for _, mem := range memberships {
		if mem.ResourceType == "ORGANIZATION" {
			orgMemberships = append(orgMemberships, mem)
		}
	}
	if len(orgMemberships) == 0 {
		return nil
	}

	target := orgMemberships[0]
	res, err := m.store.Resources().GetByBusinessID(ctx, "ORGANIZATION", target.ResourceID)
	if err != nil {
		return err
	}
	return m.setActiveResourceIAM(ctx, sessionToken, res.ID)
}
