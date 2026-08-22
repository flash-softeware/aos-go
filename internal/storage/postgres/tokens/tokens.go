package tokens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type Repository struct {
	q db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{q: q}
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

func (r *Repository) Insert(ctx context.Context, userID, tokenType, plainToken string, metadata []byte, expiresAt time.Time) error {
	if metadata == nil {
		metadata = []byte("{}")
	}
	_, err := r.q.Exec(ctx, insertToken, userID, tokenType, hashToken(plainToken), metadata, expiresAt)
	return db.MapError(err)
}

func (r *Repository) Consume(ctx context.Context, tokenHash, tokenType string) (string, error) {
	var userID string
	err := r.q.QueryRow(ctx, consumeToken, tokenHash, tokenType).Scan(&userID)
	return userID, db.MapError(err)
}

func (r *Repository) ConsumeWithMetadata(ctx context.Context, tokenHash, tokenType string) (string, []byte, error) {
	var userID string
	var metadata []byte
	err := r.q.QueryRow(ctx, consumeTokenWithMeta, tokenHash, tokenType).Scan(&userID, &metadata)
	return userID, metadata, db.MapError(err)
}
