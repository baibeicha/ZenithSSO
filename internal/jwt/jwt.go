package jwt

import (
	"AuthServer/config"
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ms = time.Millisecond
	s  = time.Second
	m  = time.Minute
	h  = time.Hour
	d  = time.Hour * 24
)

type JwtTokenProvider struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	repo       TokenRepository
	accessTTL  time.Duration
	refreshTTL time.Duration
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
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &JwtTokenProvider{
		privateKey: privateKey,
		publicKey:  publicKey,
		repo:       repo,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}, nil
}

func GetTtlUnit(unit string) time.Duration {
	switch unit {
	case "ms", "":
		return ms
	case "s":
		return s
	case "m":
		return m
	case "h":
		return h
	case "d":
		return d
	default:
		return ms
	}
}
