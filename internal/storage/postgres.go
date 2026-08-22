package storage

import (
	"context"
	"fmt"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/schema"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/audit"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/auth_accounts"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/authorization"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/invitations"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/memberships"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/mfa"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/passkeys"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/permissions"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/resources"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/roles"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/sessions"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/tokens"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/user"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresStorage struct {
	db            *pgxpool.Pool
	users         *user.UserRepository
	sessions      *sessions.SessionsRepository
	authAccounts  *auth_accounts.AuthAccountsRepository
	roles         *roles.RolesRepository
	permissions   *permissions.PermissionsRepository
	resources     *resources.ResourcesRepository
	memberships   *memberships.MembershipsRepository
	invitations   *invitations.InvitationsRepository
	authorization *authorization.Repository
	audit         *audit.Repository
	mfa           *mfa.Repository
	passkeys      *passkeys.Repository
	tokens        *tokens.Repository
}

func NewPostgres(ctx context.Context, databaseURL string) (Storage, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("postgres: database URL is required")
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	return newPostgresStorage(pool), nil
}

func NewPostgresFromPool(pool *pgxpool.Pool) Storage {
	return newPostgresStorage(pool)
}

func newPostgresStorage(pool *pgxpool.Pool) *postgresStorage {
	s := wireRepos(pool)
	s.db = pool
	return s
}

func newPostgresStorageFromQuerier(pool *pgxpool.Pool, q db.Querier) *postgresStorage {
	s := wireRepos(q)
	s.db = pool
	return s
}

func wireRepos(q db.Querier) *postgresStorage {
	return &postgresStorage{
		users:         user.NewUserRepository(q),
		sessions:      sessions.NewSessionsRepository(q),
		authAccounts:  auth_accounts.NewAuthAccountsRepository(q),
		roles:         roles.NewRolesRepository(q),
		permissions:   permissions.NewPermissionsRepository(q),
		resources:     resources.NewResourcesRepository(q),
		memberships:   memberships.NewMembershipsRepository(q),
		invitations:   invitations.NewInvitationsRepository(q),
		authorization: authorization.NewRepository(q),
		audit:         audit.NewRepository(q),
		mfa:           mfa.NewRepository(q),
		passkeys:      passkeys.NewRepository(q),
		tokens:        tokens.NewRepository(q),
	}
}

func (s *postgresStorage) Pool() *pgxpool.Pool { return s.db }

func (s *postgresStorage) Users() UserRepository                  { return s.users }
func (s *postgresStorage) Sessions() SessionRepository            { return s.sessions }
func (s *postgresStorage) AuthAccounts() AuthAccountRepository    { return s.authAccounts }
func (s *postgresStorage) Roles() RoleRepository                  { return s.roles }
func (s *postgresStorage) Permissions() PermissionRepository      { return s.permissions }
func (s *postgresStorage) Resources() ResourceRepository          { return s.resources }
func (s *postgresStorage) Memberships() MembershipRepository      { return s.memberships }
func (s *postgresStorage) Invitations() InvitationRepository      { return s.invitations }
func (s *postgresStorage) Authorization() AuthorizationRepository { return s.authorization }
func (s *postgresStorage) Audit() AuditRepository                 { return s.audit }
func (s *postgresStorage) Mfa() MfaRepository                     { return s.mfa }
func (s *postgresStorage) Passkeys() PasskeyRepository            { return s.passkeys }
func (s *postgresStorage) Tokens() TokenRepository                { return s.tokens }

func (s *postgresStorage) Transaction(ctx context.Context, fn func(tx Storage) error) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return db.MapError(err)
	}
	txStore := newPostgresStorageFromQuerier(s.db, tx)
	if err := fn(txStore); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return db.MapError(tx.Commit(ctx))
}

func (s *postgresStorage) Migrate(ctx context.Context) error {
	return schema.RunMigrations(ctx, s.db)
}

func (s *postgresStorage) Close(ctx context.Context) error {
	s.db.Close()
	return nil
}

func PoolFrom(s Storage) *pgxpool.Pool {
	if p, ok := s.(interface{ Pool() *pgxpool.Pool }); ok {
		return p.Pool()
	}
	return nil
}
