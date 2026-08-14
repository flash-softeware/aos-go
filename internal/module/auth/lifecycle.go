package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (m *Module) ForgotPassword(ctx context.Context, email string) (map[string]string, error) {
	userID, err := m.store.GetUserIDByEmail(ctx, email)
	if err != nil || userID == "" {
		return map[string]string{"message": "If an account exists, a reset link has been sent."}, nil
	}

	token := uuid.New().String() + uuid.New().String()
	expiresAt := time.Now().Add(time.Hour)

	if err := m.store.InsertUserToken(ctx, userID, "PASSWORD_RESET", token, nil, expiresAt); err != nil {
		return nil, err
	}

	return map[string]string{
		"message": "If an account exists, a reset link has been sent.",
		"token":   token,
	}, nil
}

func (m *Module) ResetPassword(ctx context.Context, token, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	tokenHash := hashToken(token)
	userID, err := m.store.ConsumeUserToken(ctx, tokenHash, "PASSWORD_RESET")
	if err != nil || userID == "" {
		return errors.New("invalid or expired reset token")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return m.store.UpdateLocalPassword(ctx, userID, string(hashed))
}

func (m *Module) ResendEmailVerification(ctx context.Context, userID string) (map[string]string, error) {
	user, err := m.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}
	if user.Status == "ACTIVE" {
		return map[string]string{"message": "Email already verified"}, nil
	}

	token := uuid.New().String() + uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := m.store.InsertUserToken(ctx, userID, "EMAIL_VERIFICATION", token, nil, expiresAt); err != nil {
		return nil, err
	}

	return map[string]string{
		"message": "Verification email sent",
		"token":   token,
	}, nil
}

func (m *Module) VerifyEmail(ctx context.Context, token string) (map[string]string, error) {
	tokenHash := hashToken(token)
	userID, err := m.store.ConsumeUserToken(ctx, tokenHash, "EMAIL_VERIFICATION")
	if err != nil || userID == "" {
		return nil, errors.New("invalid or expired verification token")
	}

	if err := m.store.ActivateUserEmail(ctx, userID); err != nil {
		return nil, err
	}

	return map[string]string{
		"message": "Email verified successfully",
		"user_id": userID,
	}, nil
}

func (m *Module) AcceptInvitation(ctx context.Context, token, password, firstName, lastName string) (*LoginResult, error) {
	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	tokenHash := hashToken(token)
	userID, metadata, err := m.store.ConsumeUserTokenWithMetadata(ctx, tokenHash, "INVITATION")
	if err != nil || userID == "" {
		return nil, errors.New("invalid or expired invitation")
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

	if err := m.store.CompleteInvitationAcceptance(ctx, userID, firstName, lastName, string(hashed)); err != nil {
		return nil, err
	}

	_ = metadata

	sessionToken, err := m.createSession(ctx, userID)
	if err != nil {
		return nil, err
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

	if err := m.store.InsertUserToken(ctx, userID, "INVITATION", token, meta, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}
