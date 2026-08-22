package sessions

import (
	"context"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type SessionsRepository struct {
	q db.Querier
}

func NewSessionsRepository(q db.Querier) *SessionsRepository {
	return &SessionsRepository{q: q}
}

func (r *SessionsRepository) Create(ctx context.Context, session *entities.Session) error {
	var activeResourceID *string
	if session.ActiveResourceID != "" {
		activeResourceID = &session.ActiveResourceID
	}
	expiresAt := time.Unix(session.ExpiresAt, 0)
	if session.ExpiresAt <= 0 {
		expiresAt = time.Now().Add(24 * time.Hour)
	}
	_, err := r.q.Exec(ctx, insertSession,
		session.ID, session.UserID, session.TokenHash, activeResourceID, expiresAt,
	)
	return db.MapError(err)
}

func (r *SessionsRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*entities.Session, error) {
	session := &entities.Session{}
	var activeResourceID *string
	err := r.q.QueryRow(ctx, selectSessionByToken, tokenHash).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &activeResourceID, &session.ExpiresAt,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	if activeResourceID != nil {
		session.ActiveResourceID = *activeResourceID
	}
	return session, nil
}

func (r *SessionsRepository) Delete(ctx context.Context, tokenHash string) error {
	_, err := r.q.Exec(ctx, revokeSession, tokenHash)
	return db.MapError(err)
}

func (r *SessionsRepository) DeleteUserSessions(ctx context.Context, userID, exceptTokenHash string) error {
	if exceptTokenHash == "" {
		_, err := r.q.Exec(ctx, revokeAllUserSessions, userID)
		return db.MapError(err)
	}
	_, err := r.q.Exec(ctx, revokeAllUserSessionsExcept, userID, exceptTokenHash)
	return db.MapError(err)
}

func (r *SessionsRepository) SetActiveResource(ctx context.Context, tokenHash, resourceID string) error {
	var activeResourceID *string
	if resourceID != "" {
		activeResourceID = &resourceID
	}
	_, err := r.q.Exec(ctx, setSessionActiveResource, tokenHash, activeResourceID)
	return db.MapError(err)
}

func (r *SessionsRepository) ListByUser(ctx context.Context, userID string) ([]response.UserSession, error) {
	rows, err := r.q.Query(ctx, listSessionsByUser, userID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var sessions []response.UserSession
	for rows.Next() {
		var s response.UserSession
		if err := rows.Scan(&s.ID, &s.IPAddress, &s.DeviceInfo, &s.CreatedAt, &s.ExpiresAt); err != nil {
			return nil, db.MapError(err)
		}
		sessions = append(sessions, s)
	}
	return sessions, db.MapError(rows.Err())
}

func (r *SessionsRepository) RevokeByID(ctx context.Context, userID, sessionID string) error {
	_, err := r.q.Exec(ctx, revokeSessionByID, sessionID, userID)
	return db.MapError(err)
}
