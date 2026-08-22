package iam

import (
	"context"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage"
)

type Engine struct {
	store storage.Storage
	cache storage.CacheRepository
}

func NewEngine(store storage.Storage, cache storage.CacheRepository) *Engine {
	return &Engine{
		store: store,
		cache: cache,
	}
}

type CanParams struct {
	UserID     string
	ResourceID string
	Permission string
	TenantID   string
}

// Can evaluates the Zanzibar-style authorization policies
func (e *Engine) Can(ctx context.Context, p CanParams) (bool, error) {
	iamResourceID, err := e.resolveIAMResourceID(ctx, p.ResourceID)
	if err != nil {
		return false, err
	}

	allowed, err := e.store.Authorization().Can(ctx, p.UserID, iamResourceID, p.Permission)
	if err != nil {
		return false, err
	}

	go func() {
		action := "AUTHORIZATION"
		decision := "DENY"
		if allowed {
			decision = "ALLOW"
		}

		bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		details := map[string]interface{}{
			"userId":     p.UserID,
			"resource":   p.ResourceID,
			"permission": p.Permission,
			"decision":   decision,
			"tenantId":   p.TenantID,
			"timestamp":  time.Now(),
		}

		_ = e.store.Audit().Insert(bgCtx, p.TenantID, p.UserID, action, "AUTHORIZATION", p.ResourceID, decision, details, "")
	}()

	return allowed, nil
}
