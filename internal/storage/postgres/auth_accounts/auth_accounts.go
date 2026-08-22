package auth_accounts

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type AuthAccountsRepository struct {
	q db.Querier
}

func NewAuthAccountsRepository(q db.Querier) *AuthAccountsRepository {
	return &AuthAccountsRepository{q: q}
}

func (r *AuthAccountsRepository) Create(ctx context.Context, account *entities.AuthAccount) error {
	provider := account.Provider
	if provider == "" {
		provider = "LOCAL"
	}
	_, err := r.q.Exec(ctx, insertAuthAccount,
		account.ID, account.UserID, provider, account.ProviderID, account.Token,
	)
	return db.MapError(err)
}

func (r *AuthAccountsRepository) GetByProvider(ctx context.Context, provider, providerUserID string) (*entities.AuthAccount, error) {
	return r.scanAccount(r.q.QueryRow(ctx, selectAuthAccountByProvider, provider, providerUserID))
}

func (r *AuthAccountsRepository) GetLocalByUserID(ctx context.Context, userID string) (*entities.AuthAccount, error) {
	return r.scanAccount(r.q.QueryRow(ctx, selectLocalAuthAccountByUserID, userID))
}

func (r *AuthAccountsRepository) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	_, err := r.q.Exec(ctx, updateLocalPassword, userID, passwordHash)
	return db.MapError(err)
}

func (r *AuthAccountsRepository) scanAccount(row interface {
	Scan(dest ...any) error
}) (*entities.AuthAccount, error) {
	account := &entities.AuthAccount{}
	err := row.Scan(&account.ID, &account.UserID, &account.Provider, &account.ProviderID, &account.Token)
	if err != nil {
		return nil, db.MapError(err)
	}
	return account, nil
}
