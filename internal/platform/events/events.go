package events

import (
	"context"
	"fmt"
	"sync"
)

// Handler processes an emitted event. Returning an error fails emission when Strict is enabled.
type Handler func(ctx context.Context, payload any) error

// Bus is an in-process event dispatcher for application hooks.
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
	Strict   bool
}

func NewBus() *Bus {
	return &Bus{handlers: make(map[string][]Handler)}
}

func (b *Bus) On(event string, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[event] = append(b.handlers[event], h)
}

func (b *Bus) Emit(ctx context.Context, event string, payload any) error {
	b.mu.RLock()
	handlers := append([]Handler(nil), b.handlers[event]...)
	b.mu.RUnlock()

	for _, h := range handlers {
		if err := h(ctx, payload); err != nil {
			if b.Strict {
				return fmt.Errorf("event %s handler: %w", event, err)
			}
		}
	}
	return nil
}

const (
	EventUserCreated         = "user.created"
	EventUserUpdated         = "user.updated"
	EventMembershipCreated   = "membership.created"
	EventRoleAssigned        = "role.assigned"
	EventInvitationAccepted  = "invitation.accepted"
)

type UserCreatedEvent struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	TenantID     string `json:"tenant_id"`
	SessionToken string `json:"session_token"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
}

type MembershipCreatedEvent struct {
	MembershipID string `json:"membership_id"`
	UserID       string `json:"user_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	TenantID     string `json:"tenant_id"`
}

type RoleAssignedEvent struct {
	MembershipID string `json:"membership_id"`
	UserID       string `json:"user_id"`
	RoleID       string `json:"role_id"`
	ResourceID   string `json:"resource_id"`
}
