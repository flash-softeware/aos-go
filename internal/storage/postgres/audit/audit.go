package audit

import (
	"context"
	"time"

	"github.com/Esubalew-Sintie/aos-auth-go/internal/constant/dto/response"
	"github.com/Esubalew-Sintie/aos-auth-go/internal/storage/postgres/db"
)

type Repository struct {
	q db.Querier
}

func NewRepository(q db.Querier) *Repository {
	return &Repository{q: q}
}

func (r *Repository) Insert(ctx context.Context, tenantID, userID, action, resourceType, resourceID, result string, details map[string]interface{}, ipAddress string) error {
	_ = tenantID
	_, err := r.q.Exec(ctx, insertAuditLog, userID, action, resourceType, resourceID, result, details, ipAddress)
	return db.MapError(err)
}

func (r *Repository) List(ctx context.Context, tenantID, action string, limit, offset int) ([]response.AuditLog, error) {
	_ = tenantID
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.q.Query(ctx, listAuditLogs, action, limit, offset)
	if err != nil {
		return nil, db.MapError(err)
	}
	defer rows.Close()

	var logs []response.AuditLog
	for rows.Next() {
		var log response.AuditLog
		var createdAt time.Time
		if err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.ResourceType, &log.ResourceID, &log.Result, &log.Details, &log.IPAddress, &createdAt); err != nil {
			return nil, db.MapError(err)
		}
		log.CreatedAt = createdAt
		logs = append(logs, log)
	}
	return logs, db.MapError(rows.Err())
}
