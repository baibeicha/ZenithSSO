package jwt

import (
	"AuthServer/internal/db"
	"fmt"
	"log/slog"
	"time"
)

type TokensRepository struct {
	DB         *db.DB
	refreshTTL time.Duration
}

func (r *TokensRepository) InBlackList(refreshToken string) bool {
	result := make([]bool, 1)
	err := r.DB.Select(&result, "SELECT EXISTS(SELECT 1 FROM tokens WHERE token = $1)", refreshToken)

	if err != nil {
		slog.Error("error checking tokens blacklist", "err", err)
		return false
	}

	if len(result) == 0 {
		return false
	}

	return result[0]
}

func (r *TokensRepository) SaveToBlackList(refreshToken string, userID string) error {
	_, err := r.DB.Exec("INSERT INTO tokens (token, expires_at, user_id) VALUES ($1, $2, $3)",
		refreshToken, time.Now().Add(r.refreshTTL).UnixMilli(), userID)
	if err != nil {
		return fmt.Errorf("error saving tokens: %w", err)
	}
	return nil
}

func NewTokensRepository(DB *db.DB, refreshTTL time.Duration) *TokensRepository {
	return &TokensRepository{
		DB:         DB,
		refreshTTL: refreshTTL,
	}
}
