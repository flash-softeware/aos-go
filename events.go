package aos

import "github.com/Esubalew-Sintie/aos-auth-go/internal/platform/events"

// Event names for application hooks.
const (
	EventUserCreated        = events.EventUserCreated
	EventUserUpdated        = events.EventUserUpdated
	EventMembershipCreated  = events.EventMembershipCreated
	EventRoleAssigned       = events.EventRoleAssigned
	EventInvitationAccepted = events.EventInvitationAccepted
)

type UserCreatedEvent = events.UserCreatedEvent
type MembershipCreatedEvent = events.MembershipCreatedEvent
type RoleAssignedEvent = events.RoleAssignedEvent
