package iam

import (
	"context"
	"time"

	"github.com/aos/sdk-go/internal/storage"
)

type Engine struct {
	store storage.Repository
	cache storage.CacheRepository
}

func NewEngine(store storage.Repository, cache storage.CacheRepository) *Engine {
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
	// Optional: Check cache here
	
	allowed, err := e.store.CheckPermission(ctx, p.UserID, p.ResourceID, p.Permission)
	if err != nil {
		return false, err
	}

	// Insert background audit log
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
		
		_ = e.store.InsertAuditLog(bgCtx, p.TenantID, p.UserID, action, "AUTHORIZATION", p.ResourceID, decision, details, "")
	}()

	return allowed, nil
}

