package aos

import (
	"context"
	"strings"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (a *AOS) Bootstrap(ctx context.Context, in BootstrapInput) (*BootstrapResult, error) {
	if _, err := a.app.Store.Roles().GetByName(ctx, "Owner"); err == nil {
		return nil, aoserrors.ErrPlatformAlreadyInitialized
	}

	if in.Owner.Email == "" || in.Owner.Password == "" {
		return nil, aoserrors.ErrOwnerCredentialsRequired
	}

	tenantName := in.TenantName
	if tenantName == "" {
		tenantName = "Default Application"
	}

	firstName := in.Owner.FirstName
	if firstName == "" {
		firstName = "Owner"
	}
	lastName := in.Owner.LastName
	if lastName == "" {
		lastName = "Admin"
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(in.Owner.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	var (
		rootBusinessID string
		orgBusinessID  string
		userID         string
	)

	err = a.app.Store.Transaction(ctx, func(tx storage.Storage) error {
		rootBusinessID = uuid.New().String()
		rootIAMID := uuid.New().String()
		if err := tx.Resources().Create(ctx, &entities.Resource{
			ID:           rootIAMID,
			ResourceType: "INSTALLATION",
			ResourceID:   rootBusinessID,
			Name:         tenantName,
		}); err != nil {
			return err
		}

		userID = uuid.New().String()
		if err := tx.Users().Create(ctx, &entities.User{
			ID:        userID,
			Email:     in.Owner.Email,
			FirstName: firstName,
			LastName:  lastName,
			Status:    "ACTIVE",
		}); err != nil {
			return err
		}

		if err := tx.AuthAccounts().Create(ctx, &entities.AuthAccount{
			ID:       uuid.New().String(),
			UserID:   userID,
			Provider: "LOCAL",
			Token:    string(hashed),
		}); err != nil {
			return err
		}

		ownerRoleID := uuid.New().String()
		if err := tx.Roles().Create(ctx, &entities.Role{
			ID:          ownerRoleID,
			Name:        "Owner",
			Description: "AOS installation administrator",
			IsSystem:    true,
		}); err != nil {
			return err
		}

		if err := tx.Permissions().Create(ctx, &entities.Permission{
			ID:           uuid.New().String(),
			Code:         "*",
			Description:  "Full access",
			ResourceType: "*",
			Action:       "*",
		}); err != nil {
			return err
		}

		if _, err := tx.Roles().GrantPermission(ctx, ownerRoleID, "*"); err != nil {
			return err
		}

		membershipID := uuid.New().String()
		if err := tx.Memberships().Create(ctx, &entities.Membership{
			ID:           membershipID,
			UserID:       userID,
			ResourceType: "INSTALLATION",
			ResourceID:   rootBusinessID,
			Status:       "ACTIVE",
		}); err != nil {
			return err
		}

		if err := tx.Memberships().AssignRole(ctx, membershipID, rootIAMID, ownerRoleID); err != nil {
			return err
		}

		if in.WithDefaultOrg {
			orgName := in.OrgName
			if orgName == "" {
				orgName = "Default Organization"
			}
			orgBusinessID = uuid.New().String()
			orgIAMID := uuid.New().String()
			if err := tx.Resources().Create(ctx, &entities.Resource{
				ID:           orgIAMID,
				ResourceType: "ORGANIZATION",
				ResourceID:   orgBusinessID,
				ParentID:     rootIAMID,
				Name:         orgName,
			}); err != nil {
				return err
			}

			orgMembershipID := uuid.New().String()
			if err := tx.Memberships().Create(ctx, &entities.Membership{
				ID:           orgMembershipID,
				UserID:       userID,
				ResourceType: "ORGANIZATION",
				ResourceID:   orgBusinessID,
				Status:       "ACTIVE",
			}); err != nil {
				return err
			}
			if err := tx.Memberships().AssignRole(ctx, orgMembershipID, orgIAMID, ownerRoleID); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	loginResult, err := a.app.Auth.Login(ctx, in.Owner.Email, in.Owner.Password)
	if err != nil {
		return nil, err
	}
	if loginResult.MfaRequired {
		return nil, aoserrors.ErrMfaRequired
	}

	return &BootstrapResult{
		Message:      "Bootstrap successful",
		TenantID:     rootBusinessID,
		UserID:       userID,
		SessionToken: loginResult.SessionToken,
		OrgID:        orgBusinessID,
	}, nil
}

func (a *AOS) GenerateResource(ctx context.Context, tenantID, resourceName string) (*GenerateResourceResult, error) {
	res, err := a.app.Management.GenerateResource(ctx, tenantID, resourceName)
	if err != nil {
		return nil, err
	}

	out := &GenerateResourceResult{
		Message: res["message"].(string),
	}
	if perms, ok := res["permissions"].([]string); ok {
		out.Permissions = perms
	}
	if roles, ok := res["roles"].([]string); ok {
		out.Roles = roles
	}
	return out, nil
}

// EnsureBootstrapInput validates bootstrap configuration.
func EnsureBootstrapInput(in BootstrapInput) error {
	if in.Owner.Email == "" || in.Owner.Password == "" {
		return aoserrors.ErrOwnerCredentialsRequired
	}
	if strings.TrimSpace(in.Owner.Email) == "" {
		return aoserrors.ErrOwnerCredentialsRequired
	}
	return nil
}
