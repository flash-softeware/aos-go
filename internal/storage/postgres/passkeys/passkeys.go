package passkeys

import (
	"context"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type Repository struct {
	q db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{q: q}
}

func (r *Repository) InsertChallenge(ctx context.Context, userID, challenge string, expiresAt time.Time) error {
	_, err := r.q.Exec(ctx, insertChallenge, userID, challenge, expiresAt)
	return db.MapError(err)
}

func (r *Repository) GetChallenge(ctx context.Context, userID string) (string, error) {
	var challenge string
	err := r.q.QueryRow(ctx, getChallenge, userID).Scan(&challenge)
	return challenge, db.MapError(err)
}

func (r *Repository) DeleteChallenge(ctx context.Context, userID string) error {
	_, err := r.q.Exec(ctx, deleteChallenge, userID)
	return db.MapError(err)
}

func (r *Repository) Insert(ctx context.Context, userID, credentialID, publicKey string, signCount int64, deviceName string, backupEligible, backedUp bool) error {
	_, err := r.q.Exec(ctx, insertPasskey, userID, credentialID, publicKey, signCount, deviceName, backupEligible, backedUp)
	return db.MapError(err)
}

func (r *Repository) List(ctx context.Context, userID string) ([]response.Passkey, error) {
	rows, err := r.q.Query(ctx, listPasskeys, userID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var out []response.Passkey
	for rows.Next() {
		var p response.Passkey
		if err := rows.Scan(&p.ID, &p.DeviceType, &p.CreatedAt); err != nil {
			return nil, db.MapError(err)
		}
		out = append(out, p)
	}
	return out, db.MapError(rows.Err())
}

func (r *Repository) ListRecords(ctx context.Context, userID string) ([]response.PasskeyRecord, error) {
	rows, err := r.q.Query(ctx, listRecords, userID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var out []response.PasskeyRecord
	for rows.Next() {
		var p response.PasskeyRecord
		if err := rows.Scan(&p.CredentialID, &p.PublicKey, &p.SignCount, &p.DeviceName, &p.BackupEligible, &p.BackedUp); err != nil {
			return nil, db.MapError(err)
		}
		out = append(out, p)
	}
	return out, db.MapError(rows.Err())
}

func (r *Repository) UpdateSignCount(ctx context.Context, userID, credentialID string, signCount int64) error {
	_, err := r.q.Exec(ctx, updateSignCount, userID, credentialID, signCount)
	return db.MapError(err)
}
