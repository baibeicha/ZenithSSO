package repository

import (
	"AuthServer/internal/domain"
	"context"
)

type SessionsRepository struct {
	db *DB
}

func NewSessionsRepository(db *DB) *SessionsRepository {
	return &SessionsRepository{db: db}
}

func (r *SessionsRepository) GetActiveSessionsByUserID(ctx context.Context, userID uint64) ([]domain.RefreshToken, error) {
	query := `
		SELECT token, user_id, client_id, ip_address, user_agent, expires_at, created_at
		FROM refresh_tokens
		WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY created_at DESC
	`
	var sessions []domain.RefreshToken
	err := r.db.SelectContext(ctx, &sessions, query, userID)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *SessionsRepository) RevokeSessionToken(ctx context.Context, token string, userID uint64) error {
	query := `DELETE FROM refresh_tokens WHERE token = $1 AND user_id = $2`
	_, err := r.db.ExecContext(ctx, query, token, userID)
	return err
}

func (r *SessionsRepository) RevokeAllSessionsExcept(ctx context.Context, userID uint64, keepToken string) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = $1 AND token != $2`
	_, err := r.db.ExecContext(ctx, query, userID, keepToken)
	return err
}
