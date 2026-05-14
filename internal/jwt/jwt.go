package jwt

import (
	"AuthServer/configs"
	"AuthServer/internal/db"
	"time"
)

const (
	ms = time.Millisecond
	s  = time.Second
	m  = time.Minute
	h  = time.Hour
	d  = time.Hour * 24
)

type JwtTokenProvider struct {
	accessTTL  uint
	refreshTTL uint
	ttlUnit    time.Duration
	secretKey  []byte
	repo       *TokensRepository
}

func NewJwtTokenProvider(cfg *configs.Config, DB *db.DB) *JwtTokenProvider {
	unit := cfg.GetString("jwt.ttl.unit")
	refreshTTL := cfg.GetUint("jwt.ttl.refresh")

	return &JwtTokenProvider{
		accessTTL:  cfg.GetUint("jwt.ttl.access"),
		refreshTTL: refreshTTL,
		ttlUnit:    getTtlUnit(unit),
		secretKey:  []byte(cfg.GetString("jwt.secret")),
		repo:       NewTokensRepository(DB, refreshTTL, getTtlUnit(unit)),
	}
}

func getTtlUnit(unit string) time.Duration {
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
