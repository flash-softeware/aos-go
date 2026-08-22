package tokens

const (
	insertToken = `INSERT INTO user_tokens (user_id, type, token_hash, metadata, expires_at) VALUES ($1, $2, $3, $4, $5)`
	consumeToken = `
		UPDATE user_tokens SET consumed_at = NOW()
		WHERE token_hash = $1 AND type = $2 AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING user_id`
	consumeTokenWithMeta = `
		UPDATE user_tokens SET consumed_at = NOW()
		WHERE token_hash = $1 AND type = $2 AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING user_id, metadata`
)
