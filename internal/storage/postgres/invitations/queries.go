package invitations

const (
	insertInvitation = `
		INSERT INTO invitations (id, email, resource_type, resource_id, role_id, invited_by, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,'')::uuid, $7, $8)`

	selectPendingInvitation = `
		SELECT id, email, resource_type, resource_id, role_id, status
		FROM invitations
		WHERE email = $1 AND resource_type = $2 AND resource_id = $3 AND status = 'PENDING'
		  AND (expires_at IS NULL OR expires_at > NOW())`

	updateInvitationStatus = `
		UPDATE invitations SET status = $2, updated_at = NOW() WHERE id = $1`
)
