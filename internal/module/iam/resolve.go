package iam

import (
	"context"

	aoserrors "github.com/Esubalew-Sintie/aos-auth-go/internal/constant/errors"
)

func (e *Engine) resolveIAMResourceID(ctx context.Context, resourceID string) (string, error) {
	if resourceID == "" {
		return "", aoserrors.ErrResourceIDRequired
	}

	if res, err := e.store.Resources().GetByID(ctx, resourceID); err == nil && res != nil {
		return res.ID, nil
	}

	for _, resourceType := range []string{"ORGANIZATION", "INSTALLATION", "PROJECT"} {
		res, err := e.store.Resources().GetByBusinessID(ctx, resourceType, resourceID)
		if err == nil && res != nil {
			return res.ID, nil
		}
	}

	return "", aoserrors.ErrResourceUnknown
}
