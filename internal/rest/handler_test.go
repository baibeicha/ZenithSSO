package rest_test

import (
	"AuthServer/internal"
	"AuthServer/internal/db"
	"AuthServer/internal/jwt"
	"AuthServer/internal/rest"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func setupTestDB() (*db.DB, sqlmock.Sqlmock, error) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		return nil, nil, err
	}
	sqlxDB := sqlx.NewDb(mockDB, "sqlmock")
	myDb := &db.DB{DB: sqlxDB}
	return myDb, mock, nil
}

type StubTokenProvider struct{}

func (s *StubTokenProvider) GenerateTokens(user *db.User, clientID string, scopes string, ip string, ua string) (*jwt.Tokens, error) {
	return &jwt.Tokens{AccessToken: "stub-access", RefreshToken: "stub-refresh"}, nil
}
func (s *StubTokenProvider) GenerateIdToken(user *db.User, clientID string, scopes string, nonce string, issuer string) (string, error) {
	return "stub-id-token", nil
}
func (s *StubTokenProvider) GenerateSessionToken(user *db.User) (string, error) { return "", nil }
func (s *StubTokenProvider) VerifyToken(tokenString string) (bool, error)       { return true, nil }
func (s *StubTokenProvider) RefreshToken(refreshToken string, user *db.User, clientID string, ip string, ua string) (*jwt.Tokens, error) {
	return &jwt.Tokens{AccessToken: "stub-access-refreshed", RefreshToken: "stub-refresh-refreshed"}, nil
}
func (s *StubTokenProvider) DeleteToken(refreshToken string) error { return nil }
func (s *StubTokenProvider) GetPublicJWKS() jwt.JWKS               { return jwt.JWKS{} }
func (s *StubTokenProvider) GetClaims(tokenString string) (*jwt.TokenClaims, error) {
	return &jwt.TokenClaims{
		Username:         "testuser",
		RegisteredClaims: jwt5.RegisteredClaims{Issuer: "1", Audience: jwt5.ClaimStrings{"test-client"}},
	}, nil
}

func setupAuthServer(dbMock *db.DB) *internal.AuthServer {
	return internal.NewAuthServer(dbMock, &StubTokenProvider{}, slog.Default(), "http://localhost:8080")
}

func TestTokenHandler_MissingClientSecret(t *testing.T) {
	myDb, _, _ := setupTestDB()
	authServer := setupAuthServer(myDb)
	handler := rest.NewAuthHandler(authServer, false, "http://localhost:8080", "")

	reqData := url.Values{}
	reqData.Set("grant_type", "authorization_code")
	reqData.Set("client_id", "test-client")
	// Missing client_secret

	req, _ := http.NewRequest("POST", "/api/v1/token", strings.NewReader(reqData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.TokenHandler(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	assert.Equal(t, "invalid_client", resp["error"])
}

func TestTokenHandler_InvalidJSON(t *testing.T) {
	myDb, _, _ := setupTestDB()
	authServer := setupAuthServer(myDb)
	handler := rest.NewAuthHandler(authServer, false, "http://localhost:8080", "")

	req, _ := http.NewRequest("POST", "/api/v1/token", bytes.NewBuffer([]byte("{invalid-json}")))
	req.Header.Set("Content-Type", "application/json") // Trigger JSON path

	rr := httptest.NewRecorder()
	handler.TokenHandler(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
