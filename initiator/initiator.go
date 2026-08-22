package initiator

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/glue/routing"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/auth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/authz"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/iam"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/management"
	meHandler "github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/me"
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

	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/crypto"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/identity"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/middleware"
	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/provider"
	webauthnplatform "github.com/Esubalew-Sintie/aos-auth-go/internal/platform/webauthn"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

type Initiator struct {
	Config Config

	Store storage.Storage
	Cache storage.CacheRepository

	Providers *provider.Registry

	Events        *events.Bus
	IAM           *iamModule.Engine
	Users         *userModule.Module
	Auth          *authModule.Module
	Organizations *organizationModule.Module
	Management    *managementModule.Module
	Memberships   *membershipModule.Module
	Roles         *rolesModule.Module
	Permissions   *permModule.Module
	Resources     *resModule.Module

	AuthMiddleware *middleware.Auth
	HTTPHandlers   HTTPHandlers
	HTTPHandler    http.Handler
}

func Init(ctx context.Context, cfg Config) (*Initiator, error) {
	normalizeConfig(&cfg)

	var pgStore storage.Storage

	switch {
	case cfg.Storage != nil:
		pgStore = cfg.Storage
	case cfg.DatabaseURL != "":
		var err error
		pgStore, err = storage.NewPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create postgres storage: %w", err)
		}
	default:
		return nil, aoserrors.ErrDatabaseURLRequired
	}

	redisAddr := cfg.RedisAddr
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	redisStore := storage.NewRedisStore(redisAddr, "", 0)

	eventBus := events.NewBus()
	eventBus.Strict = cfg.EventsStrict

	providers := provider.Build(pgStore, provider.AuthOptions{
		Password: cfg.Auth.PasswordEnabled(),
		OAuth:    toOAuthOptions(cfg.Auth.OAuth),
	})

	pluginCtx := &PluginContext{
		Store:  pgStore,
		Cache:  redisStore,
		Events: eventBus,
		Auth:   cfg.Auth,
	}
	if err := registerPlugins(ctx, cfg, pluginCtx); err != nil {
		return nil, err
	}

	iamEng := iamModule.NewEngine(pgStore, redisStore)
	usersMod := userModule.New(pgStore, eventBus)
	webauthnSvc, err := webauthnplatform.New(webauthnplatform.Config{
		RPID:      cfg.WebAuthnRPID,
		RPOrigins: cfg.WebAuthnRPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}

	var mfaBox *crypto.SecretBox
	var mfaOpts authModule.MFAOptions
	if cfg.Auth.MFA != nil {
		mfaKey := cfg.Auth.MFA.EncryptionKey
		if mfaKey == "" {
			mfaKey = os.Getenv("MFA_ENCRYPTION_KEY")
		}
		if mfaKey == "" {
			return nil, aoserrors.ErrMfaEncryptionKeyRequired
		}
		box, err := crypto.NewSecretBox(mfaKey)
		if err != nil {
			return nil, fmt.Errorf("mfa encryption key: %w", err)
		}
		mfaBox = box
		mfaOpts = authModule.MFAOptions{
			Issuer:            cfg.Auth.MFA.TOTP.Issuer,
			RecoveryCodeCount: cfg.Auth.MFA.TOTP.RecoveryCodeCount,
		}
	}

	orgOpts := authModule.OrganizationOptions{}
	orgsEnabled := false
	if cfg.Organization != nil {
		orgOpts = authModule.OrganizationOptions{
			Enabled:              cfg.Organization.Enabled,
			AutoSetActiveOnLogin: cfg.Organization.AutoSetActiveOnLoginEnabled(),
		}
		orgsEnabled = cfg.Organization.Enabled
	}

	authMod := authModule.New(pgStore, providers, webauthnSvc, mfaBox, mfaOpts, orgOpts)
	orgsMod := organizationModule.New(pgStore, orgOpts)
	rolesMod := rolesModule.New(pgStore, orgsEnabled)
	permsMod := permModule.New(pgStore, orgsEnabled)
	mgmtMod := managementModule.New(pgStore, rolesMod)
	meMod := meModule.New(pgStore, iamEng)
	membershipsMod := membershipModule.New(pgStore, eventBus)
	resourcesMod := resModule.New(pgStore)

	authHandler := auth.NewAuthHandler(authMod, meMod)
	userHandler := user.NewUserHandler(usersMod)
	orgHandler := organization.NewOrganizationHandler(orgsMod, authMod)
	iamHandler := iam.NewIamHandler(iamEng)
	authzH := authz.NewHandler(iamEng)
	mgmtHandler := management.NewManagementHandler(mgmtMod)
	meH := meHandler.NewMeHandler(meMod)

	authMW := middleware.NewAuth(authMod)

	canFn := func(ctx context.Context, userID, _, permission, tenantID string) (bool, error) {
		iamID := identity.ActiveResourceIAMIDFromContext(ctx)
		if iamID == "" {
			return false, nil
		}
		return iamEng.Can(ctx, iamModule.CanParams{
			UserID:     userID,
			ResourceID: iamID,
			Permission: permission,
			TenantID:   tenantID,
		})
	}
	requireAdmin := middleware.RequirePermission(canFn, cfg.AdminPermission, orgOpts.Enabled)

	r := routing.NewRouter(authHandler, userHandler, orgHandler, iamHandler, authzH, mgmtHandler, meH)
	httpHandler := applyPluginMiddleware(
		r.ServeHTTP(authMW.RequireSession, requireAdmin),
		cfg.Plugins,
	)

	return &Initiator{
		Config:         cfg,
		Store:          pgStore,
		Cache:          redisStore,
		Providers:      providers,
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
		HTTPHandlers: HTTPHandlers{
			Auth:         authHandler,
			User:         userHandler,
			Organization: orgHandler,
			IAM:          iamHandler,
			Authz:        authzH,
			Management:   mgmtHandler,
			Me:           meH,
		},
		HTTPHandler: httpHandler,
	}, nil
}

func (i *Initiator) Migrate(ctx context.Context) error {
	return i.Store.Migrate(ctx)
}

func toOAuthOptions(in []OAuthProviderConfig) []provider.OAuthOption {
	out := make([]provider.OAuthOption, 0, len(in))
	for _, p := range in {
		out = append(out, provider.OAuthOption{
			Name:         p.Name,
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
		})
	}
	return out
}
