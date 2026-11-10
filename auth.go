package aos

import (
	"context"
	"net/http"
)

// Auth is everything an application does with AOS. *Client (the engine
// over HTTP, such as the hosted service) has these methods, and so does
// the embedded engine (github.com/flash-software-technology/aos/embed). Write
// application code against Auth to switch between them with one line.
type Auth interface {
	// Requests
	Middleware(next http.Handler) http.Handler
	Optional(next http.Handler) http.Handler
	RequirePermission(permission string, resource ResourceFunc) func(http.Handler) http.Handler
	CanHandler() http.Handler
	VerifyToken(ctx context.Context, token string) (*Claims, error)

	// Permissions
	Can(ctx context.Context, req CanRequest) (*CanResult, error)
	CanBatch(ctx context.Context, checks []CanRequest) ([]CanResult, error)
	Filter(ctx context.Context, principalID, permission, resourceType string) (*FilterResult, error)
	Explain(ctx context.Context, req CanRequest) (map[string]any, error)
	PutPermission(ctx context.Context, p Permission) (*Permission, error)
	PutRole(ctx context.Context, r Role) (*Role, error)
	PutResource(ctx context.Context, r Resource, parent *Resource, displayName string) error
	CreateGrant(ctx context.Context, g Grant) (string, error)
	DeleteGrant(ctx context.Context, id string) error

	// Users, organizations, machines
	CreateUser(ctx context.Context, email, name, role string, on *Resource) (*User, error)
	GetUser(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context, cursor string, limit int) (*UserPage, error)
	SuspendUser(ctx context.Context, id, reason string) error
	ReinstateUser(ctx context.Context, id string) error
	DeleteUser(ctx context.Context, id string) error
	CreateOrganization(ctx context.Context, name, slug, ownerID string) (*Organization, error)
	ListOrganizations(ctx context.Context) ([]Organization, error)
	ListMembers(ctx context.Context, organizationID string) ([]Member, error)
	Invite(ctx context.Context, organizationID, email, role string) error
	CreateAPIKey(ctx context.Context, principalID, name string, scopes []string) (*APIKey, error)
	CheckAPIKey(ctx context.Context, key, permission string, on *Resource) (*KeyCheck, error)
	CreateWebhook(ctx context.Context, url string, eventTypes []string) (*Webhook, error)
}

var _ Auth = (*Client)(nil)
