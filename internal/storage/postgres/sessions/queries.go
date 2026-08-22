package sessions

const (
	insertSession = `
		INSERT INTO user_sessions (id, user_id, session_token_hash, active_resource_id, expires_at)
		VALUES ($1, $2, $3, $4, $5)`

	selectSessionByToken = `
		SELECT id, user_id, session_token_hash, active_resource_id, EXTRACT(EPOCH FROM expires_at)::bigint
		FROM user_sessions
		WHERE session_token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()`

	revokeSession = `
		UPDATE user_sessions
		SET revoked_at = NOW(), revoke_reason = 'logout'
		WHERE session_token_hash = $1 AND revoked_at IS NULL`

	revokeAllUserSessions = `
		UPDATE user_sessions
		SET revoked_at = NOW(), revoke_reason = 'revoke_all'
		WHERE user_id = $1 AND revoked_at IS NULL`

	revokeAllUserSessionsExcept = `
		UPDATE user_sessions
		SET revoked_at = NOW(), revoke_reason = 'revoke_all'
		WHERE user_id = $1 AND session_token_hash <> $2 AND revoked_at IS NULL`

	setSessionActiveResource = `
		UPDATE user_sessions
		SET active_resource_id = $2
		WHERE session_token_hash = $1 AND revoked_at IS NULL`

	listSessionsByUser = `
		SELECT id::text, COALESCE(ip_address::text, ''), device_info, created_at, expires_at
		FROM user_sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC`

	revokeSessionByID = `
		UPDATE user_sessions SET revoked_at = NOW(), revoke_reason = 'user_revoked'
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`
)
