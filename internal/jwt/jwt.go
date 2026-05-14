package jwt

import (
	"AuthServer/config"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JwtTokenProvider struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	repo       TokenRepository
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func (tp *JwtTokenProvider) GetPublicJWKS() JWKS {
	n := base64.RawURLEncoding.EncodeToString(tp.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(tp.publicKey.E)).Bytes())

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				Kid: "zenith-sso-main-key",
				N:   n,
				E:   e,
			},
		},
	}
}

func (tp *JwtTokenProvider) GetClaims(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return tp.publicKey, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token.Claims.(*TokenClaims), nil
}

func NewJwtTokenProvider(cfg *config.Config, repo TokenRepository, accessTTL, refreshTTL time.Duration) (*JwtTokenProvider, error) {
	privBytes, err := os.ReadFile(cfg.GetString("jwt.private_key_path"))
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	pubBytes, err := os.ReadFile(cfg.GetString("jwt.public_key_path"))
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	return &JwtTokenProvider{
		privateKey: privateKey,
		publicKey:  publicKey,
		repo:       repo,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

func GetTimeUnit(unit string) time.Duration {
	switch unit {
	case "s":
		return time.Second
	case "m":
		return time.Minute
	case "h":
		return time.Hour
	case "d":
		return time.Hour * 24
	default:
		return time.Minute
	}
}
