package initiator

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aos/sdk-go/internal/glue/routing"
	"github.com/aos/sdk-go/internal/handler/rest/http/auth"
	"github.com/aos/sdk-go/internal/handler/rest/http/authz"
	"github.com/aos/sdk-go/internal/handler/rest/http/iam"
	meHandler "github.com/aos/sdk-go/internal/handler/rest/http/me"
	"github.com/aos/sdk-go/internal/handler/rest/http/management"
	"github.com/aos/sdk-go/internal/handler/rest/http/organization"
	"github.com/aos/sdk-go/internal/handler/rest/http/user"

	authModule "github.com/aos/sdk-go/internal/module/auth"
	iamModule "github.com/aos/sdk-go/internal/module/iam"
	managementModule "github.com/aos/sdk-go/internal/module/management"
	meModule "github.com/aos/sdk-go/internal/module/me"
	membershipModule "github.com/aos/sdk-go/internal/module/membership"
	organizationModule "github.com/aos/sdk-go/internal/module/organization"
	permModule "github.com/aos/sdk-go/internal/module/permissions"
	resModule "github.com/aos/sdk-go/internal/module/resources"
	rolesModule "github.com/aos/sdk-go/internal/module/roles"
	userModule "github.com/aos/sdk-go/internal/module/user"

	"github.com/aos/sdk-go/internal/platform/events"
	"github.com/aos/sdk-go/internal/platform/middleware"
	webauthnplatform "github.com/aos/sdk-go/internal/platform/webauthn"
	"github.com/aos/sdk-go/internal/schema"
	"github.com/aos/sdk-go/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	DatabaseURL       string
	TenantType        string
	RedisAddr         string
	WebAuthnRPID      string
	WebAuthnRPOrigins []string
	EventsStrict      bool
}

type Initiator struct {
	DB     *pgxpool.Pool
	Config Config

	Store storage.Repository
	Cache storage.CacheRepository

	Events      *events.Bus
	IAM         *iamModule.Engine
	Users       *userModule.Module
	Auth        *authModule.Module
	Organizations *organizationModule.Module
	Management  *managementModule.Module
	Memberships *membershipModule.Module
	Roles       *rolesModule.Module
	Permissions *permModule.Module
	Resources   *resModule.Module

	AuthMiddleware *middleware.Auth
	HTTPHandler    http.Handler
}

func Init(ctx context.Context, cfg Config) (*Initiator, error) {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	pgStore := storage.NewPostgresStore(pool)

	redisAddr := cfg.RedisAddr
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisStore := storage.NewRedisStore(redisAddr, "", 0)

	eventBus := events.NewBus()
	eventBus.Strict = cfg.EventsStrict

	iamEng := iamModule.NewEngine(pgStore, redisStore)
	usersMod := userModule.New(pgStore, eventBus)
	webauthnSvc, err := webauthnplatform.New(webauthnplatform.Config{
		RPID:      cfg.WebAuthnRPID,
		RPOrigins: cfg.WebAuthnRPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}
	authMod := authModule.New(pgStore, webauthnSvc)
	orgsMod := organizationModule.New(pgStore)
	mgmtMod := managementModule.New(pgStore)
	meMod := meModule.New(pgStore, iamEng)
	membershipsMod := membershipModule.New(pgStore, eventBus)
	rolesMod := rolesModule.New(pgStore)
	permsMod := permModule.New(pgStore)
	resourcesMod := resModule.New(pgStore)

	authHandler := auth.NewAuthHandler(authMod, meMod)
	userHandler := user.NewUserHandler(usersMod)
	orgHandler := organization.NewOrganizationHandler(orgsMod)
	iamHandler := iam.NewIamHandler(iamEng)
	authzH := authz.NewHandler(iamEng)
	mgmtHandler := management.NewManagementHandler(mgmtMod)
	meH := meHandler.NewMeHandler(meMod)

	authMW := middleware.NewAuth(authMod)

	canFn := func(ctx context.Context, userID, resourceID, permission, tenantID string) (bool, error) {
		return iamEng.Can(ctx, iamModule.CanParams{
			UserID:     userID,
			ResourceID: resourceID,
			Permission: permission,
			TenantID:   tenantID,
		})
	}
	requireAdmin := middleware.RequirePermission(canFn, "user.read")

	r := routing.NewRouter(authHandler, userHandler, orgHandler, iamHandler, authzH, mgmtHandler, meH)
	httpHandler := r.ServeHTTP(authMW.RequireSession, requireAdmin)

	app := &Initiator{
		DB:             pool,
		Config:         cfg,
		Store:          pgStore,
		Cache:          redisStore,
		Events:         eventBus,
		IAM:            iamEng,
		Users:          usersMod,
		Auth:           authMod,
		Organizations:  orgsMod,
		Management:     mgmtMod,
		Memberships:    membershipsMod,
		Roles:          rolesMod,
		Permissions:    permsMod,
		Resources:      resourcesMod,
		AuthMiddleware: authMW,
		HTTPHandler:    httpHandler,
	}

	return app, nil
}

func (i *Initiator) Migrate(ctx context.Context) error {
	schemaToRun := schema.MultiTenantSchema
	if i.Config.TenantType == "single" {
		schemaToRun = strings.ReplaceAll(schemaToRun, "tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,", "")
		schemaToRun = strings.ReplaceAll(schemaToRun, "tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,", "")
	}

	_, _ = i.DB.Exec(ctx, schemaToRun)

	phaseSQL := `
		ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;
		ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id) ON DELETE SET NULL;
		ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS active_resource_id UUID;

		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id);
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS resource_type VARCHAR(50);
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS result VARCHAR(20) DEFAULT 'SUCCESS';
		ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address INET;

		CREATE TABLE IF NOT EXISTS api_keys (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID REFERENCES tenants(id),
			user_id UUID REFERENCES users(id),
			name VARCHAR(255) NOT NULL,
			key_prefix VARCHAR(16) NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
			last_used_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS webhooks (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID REFERENCES tenants(id),
			url TEXT NOT NULL,
			secret TEXT NOT NULL,
			events JSONB NOT NULL DEFAULT '[]'::jsonb,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_by UUID REFERENCES users(id),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS security_policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID REFERENCES tenants(id),
			organization_id UUID REFERENCES organizations(id),
			name VARCHAR(255) NOT NULL,
			policy_type VARCHAR(50) NOT NULL,
			configuration JSONB NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS tenant_domains (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			domain VARCHAR(255) NOT NULL,
			verified BOOLEAN DEFAULT FALSE,
			verification_token TEXT,
			verified_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(domain)
		);
		CREATE TABLE IF NOT EXISTS organization_sso_connections (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			provider VARCHAR(30) NOT NULL,
			name VARCHAR(255) NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT FALSE,
			issuer_url TEXT,
			metadata_url TEXT,
			client_id TEXT,
			client_secret_encrypted TEXT,
			certificate TEXT,
			metadata JSONB DEFAULT '{}'::jsonb,
			created_by UUID REFERENCES users(id),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS scim_connections (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			provider VARCHAR(50),
			token_hash TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			last_sync_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS organization_network_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			cidr VARCHAR(100) NOT NULL,
			description TEXT,
			enabled BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		ALTER TABLE user_tokens DROP CONSTRAINT IF EXISTS user_tokens_type_check;
		ALTER TABLE user_tokens ADD CONSTRAINT user_tokens_type_check CHECK (
			type IN (
				'EMAIL_VERIFICATION','PASSWORD_RESET','EMAIL_CHANGE','PHONE_VERIFICATION',
				'MAGIC_LINK','INVITATION','ACCOUNT_ACTIVATION','MFA_CHALLENGE'
			)
		);

		CREATE TABLE IF NOT EXISTS tenant_oauth_providers (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			provider VARCHAR(30) NOT NULL CHECK (
				provider IN ('GOOGLE', 'GITHUB', 'MICROSOFT', 'APPLE', 'OIDC')
			),
			client_id VARCHAR(255) NOT NULL,
			client_secret VARCHAR(255) NOT NULL,
			metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(tenant_id, provider)
		);
	`
	_, err := i.DB.Exec(ctx, phaseSQL)
	return err
}
