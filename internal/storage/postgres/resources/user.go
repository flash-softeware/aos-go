package resources

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type ResourcesRepository struct {
	q db.Querier
}

func NewResourcesRepository(q db.Querier) *ResourcesRepository {
	return &ResourcesRepository{q: q}
}

func (r *ResourcesRepository) Create(ctx context.Context, resource *entities.Resource) error {
	var parentID *string
	if resource.ParentID != "" {
		parentID = &resource.ParentID
	}
	_, err := r.q.Exec(ctx, insertResource,
		resource.ID, resource.ResourceType, resource.ResourceID, parentID, resource.Name,
	)
	return db.MapError(err)
}

func (r *ResourcesRepository) GetByID(ctx context.Context, id string) (*entities.Resource, error) {
	return r.scanResource(r.q.QueryRow(ctx, selectResourceByID, id))
}

func (r *ResourcesRepository) GetByBusinessID(ctx context.Context, resourceType, businessID string) (*entities.Resource, error) {
	return r.scanResource(r.q.QueryRow(ctx, selectResourceByBusinessID, resourceType, businessID))
}

func (r *ResourcesRepository) GetByType(ctx context.Context, resourceType string) (*entities.Resource, error) {
	return r.scanResource(r.q.QueryRow(ctx, selectResourceByType, resourceType))
}

func (r *ResourcesRepository) GetAncestorChain(ctx context.Context, iamResourceID string) ([]*entities.Resource, error) {
	rows, err := r.q.Query(ctx, selectResourceAncestorChain, iamResourceID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var chain []*entities.Resource
	for rows.Next() {
		resource, err := r.scanResourceRows(rows)
		if err != nil {
			return nil, err
		}
		chain = append(chain, resource)
	}
	return chain, db.MapError(rows.Err())
}

func (r *ResourcesRepository) Delete(ctx context.Context, id string) error {
	_, err := r.q.Exec(ctx, deleteResource, id)
	return db.MapError(err)
}

func (r *ResourcesRepository) scanResource(row interface {
	Scan(dest ...any) error
}) (*entities.Resource, error) {
	resource := &entities.Resource{}
	var parentID *string
	err := row.Scan(
		&resource.ID, &resource.ResourceType, &resource.ResourceID, &parentID, &resource.Name,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	if parentID != nil {
		resource.ParentID = *parentID
	}
	return resource, nil
}

func (r *ResourcesRepository) scanResourceRows(rows interface {
	Scan(dest ...any) error
}) (*entities.Resource, error) {
	return r.scanResource(rows)
}
