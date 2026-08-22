package auth_accounts

const (
	insertAuthAccount = `
		INSERT INTO auth_accounts (id, user_id, provider, provider_user_id, password_hash)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''))`

	selectAuthAccountByProvider = `
		SELECT id, user_id, provider, COALESCE(provider_user_id, ''), COALESCE(password_hash, '')
		FROM auth_accounts
		WHERE provider = $1 AND provider_user_id = $2`

	selectLocalAuthAccountByUserID = `
		SELECT id, user_id, provider, COALESCE(provider_user_id, ''), COALESCE(password_hash, '')
		FROM auth_accounts
		WHERE user_id = $1 AND provider = 'LOCAL'`

	updateLocalPassword = `
		UPDATE auth_accounts
		SET password_hash = $2, password_changed_at = NOW(), updated_at = NOW()
		WHERE user_id = $1 AND provider = 'LOCAL'`
)
