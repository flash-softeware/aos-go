package initiator

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/glue/routing"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/auth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/authz"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/iam"
	meHandler "github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/me"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/management"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/organization"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/user"

	authModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/auth"
	iamModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/iam"
	managementModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/management"
	meModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/me"
	membershipModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/membership"
	organizationModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/organization"
	permModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/permissions"
	resModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/resources"
	rolesModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/roles"
	userModule "github.com/Esubalew-Sintie/aos-auth-go/internal/module/user"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/middleware"
	webauthnplatform "github.com/Esubalew-Sintie/aos-auth-go/internal/platform/webauthn"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/schema"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
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
	return schema.RunMigrations(ctx, i.DB, i.Config.TenantType)
}
