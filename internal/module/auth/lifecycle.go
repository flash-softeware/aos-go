package auth

import (
	"context"
	"encoding/json"
	"time"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (m *Module) ForgotPassword(ctx context.Context, email string) (map[string]string, error) {
	user, err := m.store.Users().GetByEmail(ctx, email)
	if err != nil || user == nil {
		return map[string]string{"message": "If an account exists, a reset link has been sent."}, nil
	}

	token := uuid.New().String() + uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	if err := m.store.Tokens().Insert(ctx, user.ID, "PASSWORD_RESET", token, nil, expiresAt); err != nil {
		return nil, err
	}

	return map[string]string{
		"message": "If an account exists, a reset link has been sent.",
		"token":   token,
	}, nil
}

func (m *Module) ResetPassword(ctx context.Context, token, newPassword string) error {
	if len(newPassword) < 8 {
		return aoserrors.ErrPasswordTooShort
	}

	tokenHash := hashToken(token)
	userID, err := m.store.Tokens().Consume(ctx, tokenHash, "PASSWORD_RESET")
	if err != nil || userID == "" {
		return aoserrors.ErrPasswordResetTokenInvalid
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return m.store.AuthAccounts().UpdatePassword(ctx, userID, string(hashed))
}

func (m *Module) ResendEmailVerification(ctx context.Context, userID string) (map[string]string, error) {
	user, err := m.store.Users().GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, aoserrors.ErrUserNotFound
	}
	if user.Status == "ACTIVE" {
		return map[string]string{"message": "Email already verified"}, nil
	}

	token := uuid.New().String() + uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := m.store.Tokens().Insert(ctx, userID, "EMAIL_VERIFICATION", token, nil, expiresAt); err != nil {
		return nil, err
	}

	return map[string]string{
		"message": "Verification email sent",
		"token":   token,
	}, nil
}

func (m *Module) VerifyEmail(ctx context.Context, token string) (map[string]string, error) {
	tokenHash := hashToken(token)
	userID, err := m.store.Tokens().Consume(ctx, tokenHash, "EMAIL_VERIFICATION")
	if err != nil || userID == "" {
		return nil, aoserrors.ErrEmailVerificationTokenInvalid
	}

	if err := m.store.Users().Activate(ctx, userID); err != nil {
		return nil, err
	}

	return map[string]string{
		"message": "Email verified successfully",
		"user_id": userID,
	}, nil
}

func (m *Module) AcceptInvitation(ctx context.Context, token, password, firstName, lastName string) (*LoginResult, error) {
	if len(password) < 8 {
		return nil, aoserrors.ErrPasswordTooShort
	}

	tokenHash := hashToken(token)
	userID, metadata, err := m.store.Tokens().ConsumeWithMetadata(ctx, tokenHash, "INVITATION")
	if err != nil || userID == "" {
		return nil, aoserrors.ErrInvitationInvalid
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	if firstName == "" {
		firstName = "Invited"
	}
	if lastName == "" {
		lastName = "User"
	}

	if err := m.store.Users().CompleteInvitation(ctx, userID, firstName, lastName); err != nil {
		return nil, err
	}
	if _, err := m.store.AuthAccounts().GetLocalByUserID(ctx, userID); err != nil {
		if err := m.store.AuthAccounts().Create(ctx, &entities.AuthAccount{
			ID:       uuid.New().String(),
			UserID:   userID,
			Provider: "LOCAL",
			Token:    string(hashed),
		}); err != nil {
			return nil, err
		}
	} else if err := m.store.AuthAccounts().UpdatePassword(ctx, userID, string(hashed)); err != nil {
		return nil, err
	}

	var meta map[string]string
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &meta)
	}

	resourceType := meta["resource_type"]
	if resourceType == "" {
		resourceType = "ORGANIZATION"
	}
	resourceID := meta["org_id"]
	if resourceID == "" {
		resourceID = meta["resource_id"]
	}
	roleID := meta["role_id"]
	invitationID := meta["invitation_id"]

	if resourceID != "" {
		ok, err := m.store.Memberships().HasOnResource(ctx, userID, resourceID)
		if err != nil {
			return nil, err
		}
		if !ok {
			membershipID := uuid.New().String()
			if err := m.store.Memberships().Create(ctx, &entities.Membership{
				ID:           membershipID,
				UserID:       userID,
				ResourceType: resourceType,
				ResourceID:   resourceID,
				Status:       "ACTIVE",
			}); err != nil {
				return nil, err
			}

			if roleID != "" {
				iamResource, err := m.store.Resources().GetByBusinessID(ctx, resourceType, resourceID)
				if err != nil {
					return nil, err
				}
				if err := m.store.Memberships().AssignRole(ctx, membershipID, iamResource.ID, roleID); err != nil {
					return nil, err
				}
			}
		}
	}

	if invitationID != "" {
		_ = m.store.Invitations().UpdateStatus(ctx, invitationID, "ACCEPTED")
	}

	sessionToken, err := m.createSession(ctx, userID)
	if err != nil {
		return nil, err
	}

	if resourceID != "" && m.orgOpts.Enabled {
		if iamRes, resErr := m.store.Resources().GetByBusinessID(ctx, resourceType, resourceID); resErr == nil {
			_ = m.setActiveResourceIAM(ctx, sessionToken, iamRes.ID)
		}
	} else {
		_ = m.autoSetActiveOrganization(ctx, sessionToken, userID)
	}

	return &LoginResult{
		SessionToken: sessionToken,
		UserID:       userID,
	}, nil
}

func (m *Module) CreateInvitationToken(ctx context.Context, userID string, metadata map[string]string) (string, error) {
	token := uuid.New().String() + uuid.New().String()
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	var meta []byte
	if metadata != nil {
		meta, _ = json.Marshal(metadata)
	}

	if err := m.store.Tokens().Insert(ctx, userID, "INVITATION", token, meta, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}
