package user

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type UserRepository struct {
	q db.Querier
}

func NewUserRepository(q db.Querier) *UserRepository {
	return &UserRepository{q: q}
}

func (r *UserRepository) Create(ctx context.Context, user *entities.User) error {
	status := user.Status
	if status == "" {
		status = "ACTIVE"
	}
	_, err := r.q.Exec(ctx, insertUser, user.ID, user.Email, user.FirstName, user.LastName, status)
	return db.MapError(err)
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*entities.User, error) {
	user := &entities.User{}
	err := r.q.QueryRow(ctx, selectUserByID, id).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.Status,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	return user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	user := &entities.User{}
	err := r.q.QueryRow(ctx, selectUserByEmail, email).Scan(
		&user.ID, &user.Email, &user.FirstName, &user.LastName, &user.Status,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	return user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *entities.User) error {
	_, err := r.q.Exec(ctx, updateUser, user.ID, user.Email, user.FirstName, user.LastName, user.Status)
	return db.MapError(err)
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	_, err := r.q.Exec(ctx, softDeleteUser, id)
	return db.MapError(err)
}

func (r *UserRepository) Activate(ctx context.Context, userID string) error {
	_, err := r.q.Exec(ctx, activateUser, userID)
	return db.MapError(err)
}

func (r *UserRepository) CompleteInvitation(ctx context.Context, userID, firstName, lastName string) error {
	_, err := r.q.Exec(ctx, completeInvitationUser, firstName, lastName, userID)
	return db.MapError(err)
}
