package jwt

import (
	"AuthServer/internal/db"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenRepository interface {
	InBlackList(tokenString string) bool
	SaveToBlackList(tokenString, userID string) error
	CleanExpiredTokens(ctx context.Context) error
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type TokenClaims struct {
	Username string `json:"username"`
	Scopes   string `json:"scopes,omitempty"`
	jwt.RegisteredClaims
}

func (tp *JwtTokenProvider) GenerateAccess(user *db.User) (string, error) {
	claims := TokenClaims{
		Username: user.Username,
		Scopes:   user.Scopes.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strconv.FormatUint(user.ID, 10),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tp.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tp.privateKey)
}

func (tp *JwtTokenProvider) GenerateRefresh(user *db.User) (string, error) {
	claims := TokenClaims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strconv.FormatUint(user.ID, 10),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tp.refreshTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tp.privateKey)
}

func (tp *JwtTokenProvider) GenerateTokens(user *db.User) (*Tokens, error) {
	accessToken, err := tp.GenerateAccess(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := tp.GenerateRefresh(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (tp *JwtTokenProvider) VerifyToken(tokenString string) (bool, error) {
	if tokenString == "" {
		return false, nil
	}

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", t.Header["alg"])
		}
		return tp.publicKey, nil
	})

	if err != nil {
		return false, err
	}

	if tp.repo.InBlackList(tokenString) {
		return false, errors.New("token is in blacklist")
	}

	return token.Valid, nil
}

func (tp *JwtTokenProvider) RefreshToken(refreshToken string, user *db.User) (*Tokens, error) {
	isValid, err := tp.VerifyToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	if !isValid {
		return nil, errors.New("refresh token is not valid")
	}

	accessToken, err := tp.GenerateAccess(user)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (tp *JwtTokenProvider) DeleteToken(refreshToken string) error {
	token, err := jwt.ParseWithClaims(refreshToken, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", t.Header["alg"])
		}
		return tp.publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse token for deletion: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return errors.New("invalid token claims")
	}

	userID, err := claims.GetIssuer()
	if err != nil || userID == "" {
		return errors.New("failed to get user ID from token")
	}

	err = tp.repo.SaveToBlackList(refreshToken, userID)
	if err != nil {
		return fmt.Errorf("error saving token to blacklist: %w", err)
	}

	return nil
}
