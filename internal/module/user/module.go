package user

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Module struct {
	store  storage.Storage
	events *events.Bus
}

func New(store storage.Storage, bus *events.Bus) *Module {
	return &Module{store: store, events: bus}
}

type RegisterInput struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

type RegisterOutput struct {
	UserID       string `json:"user_id"`
	SessionToken string `json:"session_token"`
	Email        string `json:"email"`
}

// Register creates identity + session only. Business roles and memberships are the application's responsibility.
func (m *Module) Register(ctx context.Context, tenantID string, in RegisterInput) (*RegisterOutput, error) {
	userID := uuid.New().String()
	authAccountID := uuid.New().String()
	sessionID := uuid.New().String()
	sessionToken := uuid.New().String()
	tokenHash := hashToken(sessionToken)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	hashed, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	err = m.store.Transaction(ctx, func(tx storage.Storage) error {
		if err := tx.Users().Create(ctx, &entities.User{
			ID:        userID,
			Email:     in.Email,
			FirstName: in.FirstName,
			LastName:  in.LastName,
			Status:    "ACTIVE",
		}); err != nil {
			return err
		}

		if err := tx.AuthAccounts().Create(ctx, &entities.AuthAccount{
			ID:       authAccountID,
			UserID:   userID,
			Provider: "LOCAL",
			Token:    string(hashed),
		}); err != nil {
			return err
		}

		return tx.Sessions().Create(ctx, &entities.Session{
			ID:        sessionID,
			UserID:    userID,
			TokenHash: tokenHash,
			ExpiresAt: expiresAt,
		})
	})
	if err != nil {
		return nil, err
	}

	out := &RegisterOutput{
		UserID:       userID,
		SessionToken: sessionToken,
		Email:        in.Email,
	}

	if m.events != nil {
		_ = m.events.Emit(ctx, events.EventUserCreated, events.UserCreatedEvent{
			UserID:       userID,
			Email:        in.Email,
			TenantID:     tenantID,
			SessionToken: sessionToken,
			FirstName:    in.FirstName,
			LastName:     in.LastName,
		})
	}

	return out, nil
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
