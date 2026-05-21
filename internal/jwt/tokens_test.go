package jwt_test

import (
	"AuthServer/config"
	"AuthServer/internal/domain"
	"AuthServer/internal/jwt"
	"AuthServer/internal/repository"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
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

func generateTestKeys() (string, string) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	os.WriteFile("test_private.pem", privateKeyPEM, 0600)
	os.WriteFile("test_public.pem", publicKeyPEM, 0600)

	return "test_private.pem", "test_public.pem"
}

func TestGenerateAccess_RBAC(t *testing.T) {
	db, _, err := setupTestDB()
	assert.NoError(t, err)

	repo := repository.NewTokensRepository(db, 1*time.Hour)

	privPath, pubPath := generateTestKeys()
	defer os.Remove(privPath)
	defer os.Remove(pubPath)

	v := viper.New()
	v.Set("jwt.private_key_path", privPath)
	v.Set("jwt.public_key_path", pubPath)

	cfg := &config.Config{
		Viper: v,
	}

	provider, err := jwt.NewJwtTokenProvider(cfg, repo, 1*time.Hour, 2*time.Hour)
	assert.NoError(t, err)

	user := &domain.User{
		ID:       1,
		Username: "testuser",
		Scopes: []domain.Scope{
			{ID: 1, Name: "openid"},
			{ID: 2, Name: "urn:sso:roles"},
		},
	}

	tokenString, err := provider.GenerateAccess(user, "testclient", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	claims, err := provider.GetClaims(tokenString)
	assert.NoError(t, err)
	assert.Contains(t, claims.Scopes, "urn:sso:roles")
	assert.Contains(t, claims.Scopes, "openid")
}
