package mfa

const (
	statusRow = `SELECT enabled, verified FROM user_mfa WHERE user_id = $1 AND type = 'TOTP' LIMIT 1`
	upsertSecret = `
		INSERT INTO user_mfa (user_id, type, secret, enabled, verified)
		VALUES ($1, 'TOTP', $2, FALSE, FALSE)
		ON CONFLICT (user_id, type) DO UPDATE
		SET secret = EXCLUDED.secret, enabled = FALSE, verified = FALSE, updated_at = NOW()`
	getSecret = `SELECT secret FROM user_mfa WHERE user_id = $1 AND type = 'TOTP'`
	enableMfa = `
		UPDATE user_mfa SET enabled = TRUE, verified = TRUE, recovery_codes = $2, updated_at = NOW()
		WHERE user_id = $1 AND type = 'TOTP'`
	getWithRecovery = `
		SELECT secret, recovery_codes FROM user_mfa
		WHERE user_id = $1 AND type = 'TOTP' AND enabled = TRUE`
	updateRecovery = `UPDATE user_mfa SET recovery_codes = $2 WHERE user_id = $1 AND type = 'TOTP'`
	disableMfa = `
		UPDATE user_mfa SET enabled = FALSE, verified = FALSE, secret = NULL, recovery_codes = NULL, updated_at = NOW()
		WHERE user_id = $1 AND type = 'TOTP'`
	insertChallenge = `
		INSERT INTO user_tokens (user_id, type, token_hash, metadata, expires_at)
		VALUES ($1, 'MFA_CHALLENGE', $2, '{}'::jsonb, $3)`
	consumeChallenge = `
		UPDATE user_tokens SET consumed_at = NOW()
		WHERE token_hash = $1 AND type = 'MFA_CHALLENGE' AND consumed_at IS NULL AND expires_at > NOW()
		RETURNING user_id`
)
