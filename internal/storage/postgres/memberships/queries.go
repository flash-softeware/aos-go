package memberships

const (
	insertMembership = `
		INSERT INTO memberships (id, user_id, resource_type, resource_id, status)
		VALUES ($1, $2, $3, $4, $5)`

	selectMembership = `
		SELECT id, user_id, resource_type, resource_id, status
		FROM memberships
		WHERE user_id = $1 AND resource_type = $2 AND resource_id = $3`

	listMembershipsByUser = `
		SELECT id, user_id, resource_type, resource_id, status
		FROM memberships
		WHERE user_id = $1 AND status = 'ACTIVE'
		ORDER BY joined_at`

	insertRoleAssignment = `
		INSERT INTO role_assignments (membership_id, resource_id, role_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (membership_id, resource_id, role_id) DO NOTHING`

	removeMembership = `
		UPDATE memberships SET status = 'REMOVED', updated_at = NOW()
		WHERE id = $1`

	hasOnResource = `SELECT EXISTS(SELECT 1 FROM memberships WHERE user_id = $1 AND resource_id::text = $2 AND status = 'ACTIVE')`

	listOrganizationsForUser = `
		SELECT ir.resource_id::text, COALESCE(ir.name, ''), '' AS slug, m.id::text,
		       COALESCE(r.id::text, ''), COALESCE(r.name, '')
		FROM memberships m
		JOIN iam_resources ir ON ir.resource_id = m.resource_id AND ir.resource_type = m.resource_type
		LEFT JOIN role_assignments ra ON ra.membership_id = m.id AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		LEFT JOIN roles r ON r.id = ra.role_id
		WHERE m.user_id = $1 AND m.status = 'ACTIVE'
		ORDER BY ir.name`

	listMembers = `
		SELECT u.id::text, u.email, u.first_name, u.last_name, COALESCE(r.name, '')
		FROM memberships m
		JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
		LEFT JOIN role_assignments ra ON ra.membership_id = m.id AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		LEFT JOIN roles r ON r.id = ra.role_id
		WHERE m.resource_type = $1 AND m.resource_id::text = $2 AND m.status = 'ACTIVE'
		ORDER BY u.email`
)
