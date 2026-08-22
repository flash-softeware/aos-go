package audit

const (
	insertAuditLog = `
		INSERT INTO audit_logs (user_id, action, resource_type, resource_id, result, details, ip_address)
		VALUES (NULLIF($1,'')::uuid, $2, $3, NULLIF($4,'')::uuid, $5, $6, NULLIF($7,'')::inet)`

	listAuditLogs = `
		SELECT id, COALESCE(user_id::text, ''), action, resource_type, resource_id, result, details, COALESCE(ip_address::text, ''), created_at
		FROM audit_logs
		WHERE ($1 = '' OR action ILIKE '%' || $1 || '%')
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`
)
