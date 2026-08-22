package invitations

import (
	"context"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type InvitationsRepository struct {
	q db.Querier
}

func NewInvitationsRepository(q db.Querier) *InvitationsRepository {
	return &InvitationsRepository{q: q}
}

func (r *InvitationsRepository) Create(ctx context.Context, invitation *entities.Invitation) error {
	status := invitation.Status
	if status == "" {
		status = "PENDING"
	}
	var expiresAt *time.Time
	if invitation.ExpiresAt > 0 {
		t := time.Unix(invitation.ExpiresAt, 0)
		expiresAt = &t
	}
	_, err := r.q.Exec(ctx, insertInvitation,
		invitation.ID, invitation.Email, invitation.ResourceType, invitation.ResourceID,
		invitation.RoleID, invitation.InvitedBy, status, expiresAt,
	)
	return db.MapError(err)
}

func (r *InvitationsRepository) GetPending(ctx context.Context, email, resourceType, resourceID string) (*entities.Invitation, error) {
	invitation := &entities.Invitation{}
	err := r.q.QueryRow(ctx, selectPendingInvitation, email, resourceType, resourceID).Scan(
		&invitation.ID, &invitation.Email, &invitation.ResourceType,
		&invitation.ResourceID, &invitation.RoleID, &invitation.Status,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	return invitation, nil
}

func (r *InvitationsRepository) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := r.q.Exec(ctx, updateInvitationStatus, id, status)
	return db.MapError(err)
}
