package roles

const (
	insertRole = `
		INSERT INTO roles (id, organization_id, name, description, is_system, has_all_permissions)
		VALUES ($1, NULLIF($2, '')::uuid, $3, NULLIF($4, ''), $5, $6)`

	selectRoleByID = `
		SELECT id, COALESCE(organization_id::text, ''), name, COALESCE(description, ''), is_system, has_all_permissions
		FROM roles WHERE id = $1`

	selectSystemRoleByName = `
		SELECT id, COALESCE(organization_id::text, ''), name, COALESCE(description, ''), is_system, has_all_permissions
		FROM roles WHERE name = $1 AND organization_id IS NULL`

	selectRoleByName = `
		SELECT id, COALESCE(organization_id::text, ''), name, COALESCE(description, ''), is_system, has_all_permissions
		FROM roles WHERE name = $1 AND organization_id IS NULL`

	selectRoleByNameForOrg = `
		SELECT id, COALESCE(organization_id::text, ''), name, COALESCE(description, ''), is_system, has_all_permissions
		FROM roles WHERE name = $1 AND organization_id = $2::uuid`

	listRoles = `
		SELECT id, COALESCE(organization_id::text, ''), name, COALESCE(description, ''), is_system, has_all_permissions
		FROM roles ORDER BY name`

	deleteRole = `DELETE FROM roles WHERE id = $1`

	grantRolePermission = `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT $1, p.id FROM permissions p WHERE p.code = $2
		ON CONFLICT DO NOTHING`

	revokeRolePermission = `
		DELETE FROM role_permissions rp
		USING permissions p
		WHERE rp.role_id = $1 AND rp.permission_id = p.id AND p.code = $2`

	selectPermissionByCode = `
		SELECT id, code, COALESCE(description, ''), resource_type, action
		FROM permissions WHERE code = $1`
)
