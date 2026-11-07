package aos

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// Resource names something in the application by its type and the
// application's own id. {Type: "tenant", ID: "root"} is the top.
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// CanRequest asks "may this principal do this here?".
type CanRequest struct {
	PrincipalID string   `json:"principal_id"`
	Permission  string   `json:"permission"`
	Resource    Resource `json:"resource"`
	// SessionID lets permissions that need a fresh second factor pass.
	SessionID string `json:"session_id,omitempty"`
	// Context is what grant conditions read, such as {"request": {"amount": 500}}.
	Context map[string]any `json:"context,omitempty"`
	// AgentID, ApprovalID and Details are for agents acting for a person.
	AgentID    string         `json:"agent_id,omitempty"`
	ApprovalID string         `json:"approval_id,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	Scopes     []string       `json:"scopes,omitempty"`
}

// CanResult is the answer. A deny is an answer, not an error.
type CanResult struct {
	Allowed bool `json:"allowed"`
	// Reason is a stable code: allowed, no_matching_grant, denied_by_grant,
	// step_up_required, approval_required, condition_not_met, ...
	Reason       string `json:"reason"`
	GrantID      string `json:"grant_id,omitempty"`
	Role         string `json:"role,omitempty"`
	ApprovalID   string `json:"approval_id,omitempty"`
	DelegationID string `json:"delegation_id,omitempty"`
}

func (c *Client) Can(ctx context.Context, req CanRequest) (*CanResult, error) {
	var out CanResult
	return &out, c.do(ctx, backend, http.MethodPost, "/v1/can", req, &out)
}

// CanBatch answers up to 100 questions at once.
func (c *Client) CanBatch(ctx context.Context, checks []CanRequest) ([]CanResult, error) {
	var out struct {
		Results []CanResult `json:"results"`
	}
	err := c.do(ctx, backend, http.MethodPost, "/v1/can/batch", map[string]any{"checks": checks}, &out)
	return out.Results, err
}

// FilterResult lists the application's own ids where a permission holds.
type FilterResult struct {
	ResourceType string   `json:"resource_type"`
	Allowed      []string `json:"allowed"`
	Conditional  []string `json:"conditional"`
	Truncated    bool     `json:"truncated"`
}

// Filter says on which resources of a type a principal holds a
// permission, for the application's own list queries.
func (c *Client) Filter(ctx context.Context, principalID, permission, resourceType string) (*FilterResult, error) {
	var out FilterResult
	return &out, c.do(ctx, backend, http.MethodPost, "/v1/filter", map[string]any{"principal_id": principalID, "permission": permission, "resource_type": resourceType}, &out)
}

// Explain returns the path that decided a question, as the engine sends it.
func (c *Client) Explain(ctx context.Context, req CanRequest) (map[string]any, error) {
	var out map[string]any
	return out, c.do(ctx, backend, http.MethodPost, "/v1/explain", req, &out)
}

// Permission is something a principal may do, such as "invoice.refund".
type Permission struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	StepUpSeconds int    `json:"step_up_seconds,omitempty"`
	NeedsApproval bool   `json:"needs_approval,omitempty"`
	Source        string `json:"source,omitempty"`
}

func (c *Client) PutPermission(ctx context.Context, p Permission) (*Permission, error) {
	var out Permission
	return &out, c.do(ctx, backend, http.MethodPut, "/v1/permissions", p, &out)
}

// Role holds permission patterns: names, prefixes such as "invoice.*", or "*".
type Role struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

func (c *Client) PutRole(ctx context.Context, r Role) (*Role, error) {
	var out Role
	return &out, c.do(ctx, backend, http.MethodPut, "/v1/roles", r, &out)
}

// PutResource adds a node to the tree under parent (nil: the root).
func (c *Client) PutResource(ctx context.Context, r Resource, parent *Resource, displayName string) error {
	body := map[string]any{"type": r.Type, "id": r.ID, "display_name": displayName}
	if parent != nil {
		body["parent"] = parent
	}
	return c.do(ctx, backend, http.MethodPut, "/v1/resources", body, nil)
}

// Grant gives a role to a principal or a group on a resource.
type Grant struct {
	ID          string     `json:"id,omitempty"`
	PrincipalID string     `json:"principal_id,omitempty"`
	GroupID     string     `json:"group_id,omitempty"`
	Role        string     `json:"role"`
	Resource    Resource   `json:"resource"`
	Effect      string     `json:"effect,omitempty"` // allow (default) or deny
	Condition   string     `json:"condition,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Reason      string     `json:"reason,omitempty"`
}

func (c *Client) CreateGrant(ctx context.Context, g Grant) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, backend, http.MethodPost, "/v1/grants", g, &out)
	return out.ID, err
}

func (c *Client) DeleteGrant(ctx context.Context, id string) error {
	return c.do(ctx, backend, http.MethodDelete, "/v1/grants/"+url.PathEscape(id), nil, nil)
}
