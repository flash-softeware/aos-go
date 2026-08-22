package passkeys

const (
	insertChallenge = `INSERT INTO passkey_challenges (user_id, challenge, expires_at) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at`
	getChallenge    = `SELECT challenge FROM passkey_challenges WHERE user_id = $1 AND expires_at > NOW()`
	deleteChallenge = `DELETE FROM passkey_challenges WHERE user_id = $1`
	insertPasskey   = `INSERT INTO user_passkeys (user_id, credential_id, public_key, sign_count, device_name, backup_eligible, backed_up) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	listPasskeys    = `SELECT id, COALESCE(device_name, 'Passkey') AS device_name, created_at FROM user_passkeys WHERE user_id = $1 AND enabled = TRUE ORDER BY created_at DESC`
	listRecords     = `SELECT credential_id, public_key, sign_count, COALESCE(device_name, '') AS device_name, backup_eligible, backed_up FROM user_passkeys WHERE user_id = $1 AND enabled = TRUE`
	updateSignCount = `UPDATE user_passkeys SET sign_count = $3, last_used_at = NOW(), updated_at = NOW() WHERE user_id = $1 AND credential_id = $2`
)
