package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"github.com/google/uuid"
)

type Service struct {
	store storage.Storage
}

func New(store storage.Storage) *Service {
	return &Service{store: store}
}

func (s *Service) Create(ctx context.Context, userID string) (token string, err error) {
	sessionToken := uuid.New().String()
	tokenHash := HashToken(sessionToken)
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	err = s.store.Sessions().Create(ctx, &entities.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return "", err
	}
	return sessionToken, nil
}

func HashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
