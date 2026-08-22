package user

const (
	insertUser = `
		INSERT INTO users (id, email, first_name, last_name, status)
		VALUES ($1, $2, $3, $4, $5)`

	selectUserByID = `
		SELECT id, email, first_name, last_name, status
		FROM users
		WHERE id = $1 AND deleted_at IS NULL`

	selectUserByEmail = `
		SELECT id, email, first_name, last_name, status
		FROM users
		WHERE email = $1 AND deleted_at IS NULL`

	updateUser = `
		UPDATE users
		SET email = $2, first_name = $3, last_name = $4, status = $5, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	softDeleteUser = `
		UPDATE users
		SET deleted_at = NOW(), status = 'DELETED', updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	activateUser = `
		UPDATE users SET status = 'ACTIVE', email_verified_at = NOW(), updated_at = NOW()
		WHERE id = $1`

	completeInvitationUser = `
		UPDATE users SET first_name = $1, last_name = $2, status = 'ACTIVE', email_verified_at = NOW(), updated_at = NOW()
		WHERE id = $3`
)
