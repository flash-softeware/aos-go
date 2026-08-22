package resources

const (
	insertResource = `
		INSERT INTO iam_resources (id, resource_type, resource_id, parent_resource_id, name)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''))`

	selectResourceByID = `
		SELECT id, resource_type, resource_id, parent_resource_id, COALESCE(name, '')
		FROM iam_resources WHERE id = $1`

	selectResourceByBusinessID = `
		SELECT id, resource_type, resource_id, parent_resource_id, COALESCE(name, '')
		FROM iam_resources
		WHERE resource_type = $1 AND resource_id = $2`

	selectResourceByType = `
		SELECT id, resource_type, resource_id, parent_resource_id, COALESCE(name, '')
		FROM iam_resources
		WHERE resource_type = $1
		ORDER BY created_at
		LIMIT 1`

	selectResourceAncestorChain = `
		WITH RECURSIVE chain AS (
			SELECT id, resource_type, resource_id, parent_resource_id, name
			FROM iam_resources WHERE id = $1
			UNION ALL
			SELECT r.id, r.resource_type, r.resource_id, r.parent_resource_id, r.name
			FROM iam_resources r
			INNER JOIN chain c ON r.id = c.parent_resource_id
		)
		SELECT id, resource_type, resource_id, parent_resource_id, COALESCE(name, '')
		FROM chain`

	deleteResource = `DELETE FROM iam_resources WHERE id = $1`
)
