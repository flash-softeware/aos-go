package user

import (
	"context"
	"fmt"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Module struct {
	store  storage.Repository
	events *events.Bus
}

func New(store storage.Repository, bus *events.Bus) *Module {
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
	if tenantID == "" {
		id, err := m.store.GetFirstTenantID(ctx)
		if err != nil || id == "" {
			return nil, fmt.Errorf("tenant_id is required")
		}
		tenantID = id
	}

	tx, err := m.store.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	hashed, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	userID, err := m.store.InsertUser(ctx, tx, in.Email, in.FirstName, in.LastName)
	if err != nil {
		return nil, err
	}

	if err := m.store.InsertAuthAccount(ctx, tx, userID, string(hashed)); err != nil {
		return nil, err
	}

	sessionToken := uuid.New().String()
	tokenHash := hashToken(sessionToken)
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := m.store.InsertSession(ctx, tx, userID, tenantID, "", "", tokenHash, expiresAt); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
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
