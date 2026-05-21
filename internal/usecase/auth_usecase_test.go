package usecase_test

import (
	"AuthServer/internal/repository"
	"AuthServer/internal/usecase"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func setupTestDB() (*repository.DB, sqlmock.Sqlmock, error) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		return nil, nil, err
	}
	sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
	myDb := &repository.DB{DB: sqlxDB}
	return myDb, mock, nil
}

func TestAuthUsecase_ExchangeAuthorizationCode_MismatchedRedirectURI(t *testing.T) {
	db, mock, err := setupTestDB()
	assert.NoError(t, err)

	userRepo := repository.NewUserRepository(db)
	clientRepo := repository.NewClientsRepository(db)
	authCodesRepo := repository.NewAuthCodesRepository(db)
	authService := usecase.NewAuthUsecase(userRepo, clientRepo, authCodesRepo, nil, slog.Default(), "http://localhost")

	mock.ExpectQuery("^DELETE FROM auth_codes WHERE code = \\$1 RETURNING (.+)$").
		WithArgs("valid-code").
		WillReturnRows(sqlmock.NewRows([]string{"code", "client_id", "user_id", "redirect_uri", "code_challenge", "code_challenge_method", "scopes", "nonce", "expires_at"}).
			AddRow("valid-code", "client1", 1, "http://correct-uri", "challenge", "plain", "openid", "nonce", time.Now().Add(1*time.Hour)))

	_, err = authService.ExchangeAuthorizationCode(context.Background(), "valid-code", "client1", "http://wrong-uri", "verifier", "ip", "ua")
	assert.Error(t, err)
	assert.Equal(t, "invalid redirect_uri", err.Error())
}

func TestSessionUsecase_RevokeSession(t *testing.T) {
	db, mock, err := setupTestDB()
	assert.NoError(t, err)

	sessionRepo := repository.NewSessionsRepository(db)
	sessionService := usecase.NewSessionUsecase(sessionRepo)

	mock.ExpectExec("^DELETE FROM refresh_tokens WHERE token = \\$1 AND user_id = \\$2$").
		WithArgs("token-to-revoke", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = sessionService.RevokeSession(context.Background(), 1, "token-to-revoke")
	assert.NoError(t, err)
}

func TestSessionUsecase_RevokeAllExceptCurrent(t *testing.T) {
	db, mock, err := setupTestDB()
	assert.NoError(t, err)

	sessionRepo := repository.NewSessionsRepository(db)
	sessionService := usecase.NewSessionUsecase(sessionRepo)

	mock.ExpectExec("^DELETE FROM refresh_tokens WHERE user_id = \\$1 AND token != \\$2$").
		WithArgs(1, "current-token").
		WillReturnResult(sqlmock.NewResult(1, 2))

	err = sessionService.RevokeAllExceptCurrent(context.Background(), 1, "current-token")
	assert.NoError(t, err)
}
