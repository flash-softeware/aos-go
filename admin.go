package aos

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// User is a person's account.
type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name,omitempty"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

// CreateUser makes an account and emails the person a setup link. With a
// role and a resource, they hold that role from the start.
func (c *Client) CreateUser(ctx context.Context, email, name, role string, on *Resource) (*User, error) {
	body := map[string]any{"email": email, "name": name}
	if role != "" {
		body["role"] = role
		if on == nil {
			on = &Resource{Type: "tenant", ID: "root"}
		}
		body["resource"] = on
	}
	var out User
	return &out, c.do(ctx, backend, http.MethodPost, "/v1/users", body, &out)
}

func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	var out User
	return &out, c.do(ctx, backend, http.MethodGet, "/v1/users/"+url.PathEscape(id), nil, &out)
}

// UserPage is one page of users.
type UserPage struct {
	Users      []User `json:"users"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func (c *Client) ListUsers(ctx context.Context, cursor string, limit int) (*UserPage, error) {
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out UserPage
	return &out, c.do(ctx, backend, http.MethodGet, "/v1/users?"+q.Encode(), nil, &out)
}

func (c *Client) SuspendUser(ctx context.Context, id, reason string) error {
	return c.do(ctx, backend, http.MethodPost, "/v1/users/"+url.PathEscape(id)+"/suspend", map[string]string{"reason": reason}, nil)
}

func (c *Client) ReinstateUser(ctx context.Context, id string) error {
	return c.do(ctx, backend, http.MethodPost, "/v1/users/"+url.PathEscape(id)+"/reinstate", nil, nil)
}

func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.do(ctx, backend, http.MethodDelete, "/v1/users/"+url.PathEscape(id), nil, nil)
}

// Organization is a customer of the application.
type Organization struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateOrganization makes an organization. ownerID, when set, is its first Owner.
func (c *Client) CreateOrganization(ctx context.Context, name, slug, ownerID string) (*Organization, error) {
	var out Organization
	return &out, c.do(ctx, backend, http.MethodPost, "/v1/admin/organizations", map[string]any{"name": name, "slug": slug, "owner_principal_id": ownerID}, &out)
}

func (c *Client) ListOrganizations(ctx context.Context) ([]Organization, error) {
	var out []Organization
	return out, c.do(ctx, backend, http.MethodGet, "/v1/admin/organizations", nil, &out)
}

// Member is a person with roles in an organization.
type Member struct {
	PrincipalID string   `json:"principal_id"`
	Email       string   `json:"email,omitempty"`
	Name        string   `json:"name,omitempty"`
	Status      string   `json:"status"`
	Roles       []string `json:"roles"`
}

func (c *Client) ListMembers(ctx context.Context, organizationID string) ([]Member, error) {
	var out []Member
	return out, c.do(ctx, backend, http.MethodGet, "/v1/admin/organizations/"+url.PathEscape(organizationID)+"/members", nil, &out)
}

// Invite sends an invitation to join an organization with a role.
func (c *Client) Invite(ctx context.Context, organizationID, email, role string) error {
	return c.do(ctx, backend, http.MethodPost, "/v1/admin/organizations/"+url.PathEscape(organizationID)+"/invitations", map[string]any{"email": email, "role": role}, nil)
}

// APIKey is a key issued to a principal. Key is set only when created.
type APIKey struct {
	ID          string   `json:"id"`
	PrincipalID string   `json:"principal_id"`
	Name        string   `json:"name"`
	PublicID    string   `json:"public_id"`
	Scopes      []string `json:"scopes"`
	Key         string   `json:"key,omitempty"`
}

func (c *Client) CreateAPIKey(ctx context.Context, principalID, name string, scopes []string) (*APIKey, error) {
	var out APIKey
	return &out, c.do(ctx, backend, http.MethodPost, "/v1/api-keys", map[string]any{"principal_id": principalID, "name": name, "scopes": scopes}, &out)
}

// KeyCheck is who an API key is, and the answer to its question.
type KeyCheck struct {
	KeyID       string   `json:"key_id"`
	PrincipalID string   `json:"principal_id"`
	Kind        string   `json:"kind"`
	Scopes      []string `json:"scopes"`
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason,omitempty"`
}

// CheckAPIKey identifies a key a caller presented and, with a permission,
// checks it within the key's scopes. An unknown or revoked key is an
// APIError with code "invalid_api_key".
func (c *Client) CheckAPIKey(ctx context.Context, key, permission string, on *Resource) (*KeyCheck, error) {
	body := map[string]any{"key": key}
	if permission != "" {
		body["permission"] = permission
		if on == nil {
			on = &Resource{Type: "tenant", ID: "root"}
		}
		body["resource"] = on
	}
	var out KeyCheck
	return &out, c.do(ctx, backend, http.MethodPost, "/v1/api-keys/check", body, &out)
}

// Webhook is an endpoint the engine posts events to. Secret is set only
// when created.
type Webhook struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	URL        string   `json:"url"`
	EventTypes []string `json:"event_types"`
	Secret     string   `json:"secret,omitempty"`
}

func (c *Client) CreateWebhook(ctx context.Context, url string, eventTypes []string) (*Webhook, error) {
	var out Webhook
	return &out, c.do(ctx, backend, http.MethodPost, "/v1/webhooks", map[string]any{"url": url, "event_types": eventTypes}, &out)
}
