package initiator

import (
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/auth"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/authz"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/iam"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/management"
	meHandler "github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/me"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/organization"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/handler/rest/http/user"
)

// HTTPHandlers holds wired HTTP handler implementations used by the public SDK facades.
type HTTPHandlers struct {
	Auth         *auth.AuthHandler
	User         *user.UserHandler
	Organization *organization.OrganizationHandler
	IAM          *iam.IamHandler
	Authz        *authz.Handler
	Management   *management.ManagementHandler
	Me           *meHandler.MeHandler
}
