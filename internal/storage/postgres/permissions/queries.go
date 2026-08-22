package permissions

const (
	insertPermission = `
		INSERT INTO permissions (id, resource_type, action, code, description)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''))`

	selectPermissionByCode = `
		SELECT id, code, COALESCE(description, ''), resource_type, action
		FROM permissions WHERE code = $1`

	listPermissions = `
		SELECT id, code, COALESCE(description, ''), resource_type, action
		FROM permissions ORDER BY code`
)
