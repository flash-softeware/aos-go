package audit

import (
	"context"
	"encoding/json"

	"github.com/Esubalew-Sintie/aos-auth-go/initiator"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"
)

// Plugin writes lifecycle events to audit_logs.
type Plugin struct{}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Name() string {
	return "audit"
}

func (p *Plugin) Register(_ context.Context, pc *initiator.PluginContext) error {
	pc.Events.On(events.EventUserCreated, func(ctx context.Context, payload any) error {
		ev, ok := payload.(events.UserCreatedEvent)
		if !ok {
			return nil
		}
		details, _ := json.Marshal(map[string]string{
			"email":      ev.Email,
			"first_name": ev.FirstName,
			"last_name":  ev.LastName,
		})
		return pc.Store.Audit().Insert(ctx, ev.TenantID, ev.UserID, "USER_CREATED", "USER", ev.UserID, "SUCCESS", map[string]interface{}{
			"details": string(details),
		}, "")
	})

	pc.Events.On(events.EventMembershipCreated, func(ctx context.Context, payload any) error {
		ev, ok := payload.(events.MembershipCreatedEvent)
		if !ok {
			return nil
		}
		return pc.Store.Audit().Insert(ctx, ev.TenantID, ev.UserID, "MEMBERSHIP_CREATED", ev.ResourceType, ev.ResourceID, "SUCCESS", map[string]interface{}{
			"membership_id": ev.MembershipID,
		}, "")
	})

	pc.Events.On(events.EventRoleAssigned, func(ctx context.Context, payload any) error {
		ev, ok := payload.(events.RoleAssignedEvent)
		if !ok {
			return nil
		}
		return pc.Store.Audit().Insert(ctx, "", ev.UserID, "ROLE_ASSIGNED", "ROLE", ev.RoleID, "SUCCESS", map[string]interface{}{
			"membership_id": ev.MembershipID,
			"resource_id":   ev.ResourceID,
		}, "")
	})

	return nil
}
