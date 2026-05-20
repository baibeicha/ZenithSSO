package repository

import (
	"AuthServer/internal/domain"
	"context"
)

type AuthCodesRepository struct {
	db *DB
}

func NewAuthCodesRepository(db *DB) *AuthCodesRepository {
	return &AuthCodesRepository{db: db}
}

func (r *AuthCodesRepository) SaveCode(ctx context.Context, code *domain.AuthCode) error {
	query := `
		INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, scopes, nonce, expires_at)
		VALUES (:code, :client_id, :user_id, :redirect_uri, :code_challenge, :code_challenge_method, :scopes, :nonce, :expires_at)
	`
	_, err := r.db.NamedExecContext(ctx, query, code)
	return err
}

func (r *AuthCodesRepository) GetAndDeleteCode(ctx context.Context, code string) (*domain.AuthCode, error) {
	var authCode domain.AuthCode
	query := `
		DELETE FROM auth_codes 
		WHERE code = $1 
		RETURNING code, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, scopes, nonce, expires_at
	`
	err := r.db.GetContext(ctx, &authCode, query, code)
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}
