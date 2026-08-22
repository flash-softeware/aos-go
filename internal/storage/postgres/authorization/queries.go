package authorization

const (
	checkPermission = `
		WITH RECURSIVE resource_tree AS (
			SELECT id, parent_resource_id, resource_id as raw_resource_id
			FROM iam_resources
			WHERE id = $2::uuid
			UNION ALL
			SELECT ir.id, ir.parent_resource_id, ir.resource_id as raw_resource_id
			FROM iam_resources ir
			INNER JOIN resource_tree rt ON rt.parent_resource_id = ir.id
		),
		matched_assignments AS (
			SELECT ra.effect
			FROM memberships m
			JOIN role_assignments ra ON ra.membership_id = m.id
			JOIN roles r ON r.id = ra.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id
			WHERE m.user_id = $1
			  AND m.status = 'ACTIVE'
			  AND m.resource_id::text IN (SELECT raw_resource_id::text FROM resource_tree)
			  AND ra.resource_id IN (SELECT id FROM resource_tree)
			  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
			  AND (
				  r.has_all_permissions = TRUE
				  OR p.code = $3
				  OR p.code = split_part($3, '.', 1) || '.*'
				  OR p.code = split_part($3, '.', 1) || '.' || split_part($3, '.', 2) || '.*'
				  OR p.code = '*'
			  )
		)
		SELECT
			CASE
				WHEN EXISTS (SELECT 1 FROM matched_assignments WHERE effect = 'DENY') THEN false
				WHEN EXISTS (SELECT 1 FROM matched_assignments WHERE effect = 'ALLOW') THEN true
				ELSE false
			END`

	permissionCodes = `
		SELECT DISTINCT p.code
		FROM memberships m
		JOIN role_assignments ra ON ra.membership_id = m.id AND ra.effect = 'ALLOW'
		JOIN roles r ON r.id = ra.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id
		WHERE m.user_id = $1 AND m.resource_id::text = $2 AND m.status = 'ACTIVE'
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		  AND (r.has_all_permissions = TRUE OR p.code IS NOT NULL)
		ORDER BY p.code`
)
