package jwt

import (
	"AuthServer/internal/db"
	"context"
	"fmt"
	"log/slog"
	"time"
)

type TokensRepository struct {
	DB         *db.DB
	refreshTTL time.Duration
}

func (r *TokensRepository) IsTokenValid(refreshToken string) bool {
	result := make([]bool, 1)
	err := r.DB.Select(&result, "SELECT EXISTS(SELECT 1 FROM refresh_tokens WHERE token = $1 AND expires_at > NOW())", refreshToken)

	if err != nil {
		slog.Error("error checking token whitelist", "err", err)
		return false
	}

	if len(result) == 0 {
		return false
	}

	return result[0]
}

func (r *TokensRepository) SaveToWhiteList(refreshToken string, userID string, clientID string, ipAddress string, userAgent string) error {
	_, err := r.DB.Exec("INSERT INTO refresh_tokens (token, user_id, client_id, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5, $6)",
		refreshToken, userID, clientID, ipAddress, userAgent, time.Now().Add(r.refreshTTL))
	if err != nil {
		return fmt.Errorf("error saving token to whitelist: %w", err)
	}
	return nil
}

func (r *TokensRepository) RevokeToken(refreshToken string) error {
	_, err := r.DB.Exec("DELETE FROM refresh_tokens WHERE token = $1", refreshToken)
	return err
}

func (r *TokensRepository) CleanExpiredTokens(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`

	_, err := r.DB.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to clean expired tokens: %w", err)
	}

	return nil
}

func NewTokensRepository(DB *db.DB, refreshTTL time.Duration) *TokensRepository {
	return &TokensRepository{
		DB:         DB,
		refreshTTL: refreshTTL,
	}
}
