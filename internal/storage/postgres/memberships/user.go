package memberships

import (
	"context"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/entities"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type MembershipsRepository struct {
	q db.Querier
}

func NewMembershipsRepository(q db.Querier) *MembershipsRepository {
	return &MembershipsRepository{q: q}
}

func (r *MembershipsRepository) Create(ctx context.Context, membership *entities.Membership) error {
	status := membership.Status
	if status == "" {
		status = "ACTIVE"
	}
	_, err := r.q.Exec(ctx, insertMembership,
		membership.ID, membership.UserID, membership.ResourceType, membership.ResourceID, status,
	)
	return db.MapError(err)
}

func (r *MembershipsRepository) Get(ctx context.Context, userID, resourceType, resourceID string) (*entities.Membership, error) {
	membership := &entities.Membership{}
	err := r.q.QueryRow(ctx, selectMembership, userID, resourceType, resourceID).Scan(
		&membership.ID, &membership.UserID, &membership.ResourceType, &membership.ResourceID, &membership.Status,
	)
	if err != nil {
		return nil, db.MapError(err)
	}
	return membership, nil
}

func (r *MembershipsRepository) ListByUser(ctx context.Context, userID string) ([]*entities.Membership, error) {
	rows, err := r.q.Query(ctx, listMembershipsByUser, userID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var memberships []*entities.Membership
	for rows.Next() {
		m := &entities.Membership{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.ResourceType, &m.ResourceID, &m.Status); err != nil {
			return nil, db.MapError(err)
		}
		memberships = append(memberships, m)
	}
	return memberships, db.MapError(rows.Err())
}

func (r *MembershipsRepository) AssignRole(ctx context.Context, membershipID, iamResourceID, roleID string) error {
	_, err := r.q.Exec(ctx, insertRoleAssignment, membershipID, iamResourceID, roleID)
	return db.MapError(err)
}

func (r *MembershipsRepository) Remove(ctx context.Context, id string) error {
	_, err := r.q.Exec(ctx, removeMembership, id)
	return db.MapError(err)
}

func (r *MembershipsRepository) HasOnResource(ctx context.Context, userID, resourceID string) (bool, error) {
	var ok bool
	err := r.q.QueryRow(ctx, hasOnResource, userID, resourceID).Scan(&ok)
	return ok, db.MapError(err)
}

func (r *MembershipsRepository) ListOrganizationsForUser(ctx context.Context, userID string) ([]response.UserOrganization, error) {
	rows, err := r.q.Query(ctx, listOrganizationsForUser, userID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var orgs []response.UserOrganization
	for rows.Next() {
		var o response.UserOrganization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.MembershipID, &o.RoleID, &o.RoleName); err != nil {
			return nil, db.MapError(err)
		}
		orgs = append(orgs, o)
	}
	return orgs, db.MapError(rows.Err())
}

func (r *MembershipsRepository) ListMembers(ctx context.Context, resourceType, resourceID string) ([]response.OrgMember, error) {
	rows, err := r.q.Query(ctx, listMembers, resourceType, resourceID)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var members []response.OrgMember
	for rows.Next() {
		var m response.OrgMember
		if err := rows.Scan(&m.UserID, &m.Email, &m.FirstName, &m.LastName, &m.RoleName); err != nil {
			return nil, db.MapError(err)
		}
		members = append(members, m)
	}
	return members, db.MapError(rows.Err())
}
