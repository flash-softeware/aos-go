package aos

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const defaultTenantType = "APPLICATION"

func (a *AOS) Bootstrap(ctx context.Context, in BootstrapInput) (*BootstrapResult, error) {
	count, err := a.App.Store.CountTenants(ctx)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, errors.New("platform already initialized")
	}

	if in.Owner.Email == "" || in.Owner.Password == "" {
		return nil, errors.New("owner email and password are required")
	}

	tx, err := a.App.Store.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	tenantName := in.TenantName
	if tenantName == "" {
		tenantName = "Default Application"
	}
	slug := strings.ToLower(strings.ReplaceAll(tenantName, " ", "-"))

	tenantID, err := a.App.Store.InsertTenant(ctx, tx, tenantName, slug, defaultTenantType)
	if err != nil {
		return nil, err
	}

	if err := a.App.Store.InsertTenantResource(ctx, tx, tenantID); err != nil {
		return nil, err
	}

	var orgID string
	if in.WithDefaultOrg {
		orgName := in.OrgName
		if orgName == "" {
			orgName = "Default Organization"
		}
		orgSlug := strings.ToLower(strings.ReplaceAll(orgName, " ", "-"))
		orgID, err = a.App.Store.InsertOrganization(ctx, tx, tenantID, orgName, orgSlug)
		if err != nil {
			return nil, err
		}
		if err := a.App.Store.InsertOrgResource(ctx, tx, tenantID, orgID); err != nil {
			return nil, err
		}
	}

	firstName := in.Owner.FirstName
	if firstName == "" {
		firstName = "Owner"
	}
	lastName := in.Owner.LastName
	if lastName == "" {
		lastName = "Admin"
	}

	userID, err := a.App.Store.InsertUser(ctx, tx, in.Owner.Email, firstName, lastName)
	if err != nil {
		return nil, err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(in.Owner.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	if err := a.App.Store.InsertAuthAccount(ctx, tx, userID, string(hashed)); err != nil {
		return nil, err
	}

	ownerRoleID, err := a.App.Store.InsertSystemRole(ctx, tx, tenantID, "Owner", "AOS installation administrator", true)
	if err != nil {
		return nil, err
	}

	permID, err := a.App.Store.InsertPermission(ctx, tx, "*", "*", "*", "Full access")
	if err != nil {
		return nil, err
	}
	if err := a.App.Store.InsertRolePerm(ctx, tx, ownerRoleID, permID); err != nil {
		return nil, err
	}

	membershipID, err := a.App.Store.InsertMembership(ctx, tx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	iamResourceID, err := a.App.Store.GetIAMResource(ctx, tx, tenantID, "TENANT")
	if err != nil {
		return nil, err
	}
	if err := a.App.Store.InsertRoleAssignment(ctx, tx, membershipID, iamResourceID, ownerRoleID); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	loginResult, err := a.App.Auth.Login(ctx, in.Owner.Email, in.Owner.Password)
	if err != nil {
		return nil, err
	}
	if loginResult.MfaRequired {
		return nil, errors.New("MFA required during bootstrap")
	}

	return &BootstrapResult{
		Message:      "Bootstrap successful",
		TenantID:     tenantID,
		UserID:       userID,
		SessionToken: loginResult.SessionToken,
		OrgID:        orgID,
	}, nil
}

func (a *AOS) GenerateResource(ctx context.Context, tenantID, resourceName string) (*GenerateResourceResult, error) {
	res, err := a.App.Management.GenerateResource(ctx, tenantID, resourceName)
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
		return fmt.Errorf("owner email and password are required")
	}
	return nil
}
