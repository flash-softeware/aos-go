package password

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/result"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider/session"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type Provider struct {
	store    storage.Storage
	sessions *session.Service
}

func New(store storage.Storage) *Provider {
	return &Provider{
		store:    store,
		sessions: session.New(store),
	}
}

func (p *Provider) Name() string { return "password" }

func (p *Provider) Login(ctx context.Context, email, password string) (*result.Auth, error) {
	user, err := p.store.Users().GetByEmail(ctx, email)
	if err != nil {
		return nil, errors.ErrInvalidCredentials
	}

	account, err := p.store.AuthAccounts().GetLocalByUserID(ctx, user.ID)
	if err != nil {
		return nil, errors.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(account.Token), []byte(password)); err != nil {
		return nil, errors.ErrInvalidCredentials
	}

	sessionToken, err := p.sessions.Create(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	return &result.Auth{
		SessionToken: sessionToken,
		UserID:       user.ID,
	}, nil
}
