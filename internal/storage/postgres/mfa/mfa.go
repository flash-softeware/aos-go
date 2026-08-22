package mfa

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
	"github.com/jackc/pgx/v5"
)

type Repository struct {
	q db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{q: q}
}

func (r *Repository) Status(ctx context.Context, userID string) (bool, bool, error) {
	var enabled, verified bool
	err := r.q.QueryRow(ctx, statusRow, userID).Scan(&enabled, &verified)
	if err == pgx.ErrNoRows {
		return false, false, nil
	}
	if err != nil {
		return false, false, db.MapError(err)
	}
	return enabled, verified, nil
}

func (r *Repository) UpsertSecret(ctx context.Context, userID, secret string) error {
	_, err := r.q.Exec(ctx, upsertSecret, userID, secret)
	return db.MapError(err)
}

func (r *Repository) GetSecret(ctx context.Context, userID string) (string, error) {
	var secret *string
	err := r.q.QueryRow(ctx, getSecret, userID).Scan(&secret)
	if err == pgx.ErrNoRows || secret == nil {
		return "", nil
	}
	return *secret, db.MapError(err)
}

func (r *Repository) Enable(ctx context.Context, userID string, recoveryCodeHashes []string) error {
	raw, _ := json.Marshal(recoveryCodeHashes)
	_, err := r.q.Exec(ctx, enableMfa, userID, raw)
	return db.MapError(err)
}

func (r *Repository) GetWithRecovery(ctx context.Context, userID string) (string, []string, error) {
	var secret *string
	var raw []byte
	err := r.q.QueryRow(ctx, getWithRecovery, userID).Scan(&secret, &raw)
	if err == pgx.ErrNoRows || secret == nil {
		return "", nil, errors.ErrNotFound
	}
	if err != nil {
		return "", nil, db.MapError(err)
	}
	var codes []string
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &codes)
	}
	return *secret, codes, nil
}

func (r *Repository) UpdateRecoveryCodes(ctx context.Context, userID string, recoveryCodeHashes []string) error {
	raw, _ := json.Marshal(recoveryCodeHashes)
	_, err := r.q.Exec(ctx, updateRecovery, userID, raw)
	return db.MapError(err)
}

func (r *Repository) Disable(ctx context.Context, userID string) error {
	_, err := r.q.Exec(ctx, disableMfa, userID)
	return db.MapError(err)
}

func (r *Repository) InsertChallenge(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := r.q.Exec(ctx, insertChallenge, userID, tokenHash, expiresAt)
	return db.MapError(err)
}

func (r *Repository) ConsumeChallenge(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	err := r.q.QueryRow(ctx, consumeChallenge, tokenHash).Scan(&userID)
	return userID, db.MapError(err)
}
