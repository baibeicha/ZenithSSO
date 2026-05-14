package jwt

import (
	"AuthServer/internal/db"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tp.ttlUnit * time.Duration(tp.accessTTL))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(tp.secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (tp *JwtTokenProvider) GenerateRefresh(user *db.User) (string, error) {
	claims := TokenClaims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strconv.FormatUint(user.ID, 10),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tp.ttlUnit * time.Duration(tp.refreshTTL))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(tp.secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (tp *JwtTokenProvider) GenerateTokens(user *db.User) (*Tokens, error) {
	accessToken, err := tp.GenerateAccess(user)
	if err != nil {
		return nil, err
	}
	refreshToken, err := tp.GenerateRefresh(user)
	if err != nil {
		return nil, err
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

	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", token.Header["alg"])
		}
		return tp.secretKey, nil
	})

	if err != nil {
		return false, err
	}

	if tp.repo.InBlackList(tokenString) {
		return false, nil
	}

	return token.Valid, nil
}

func (tp *JwtTokenProvider) RefreshToken(refreshToken string, user *db.User) (*Tokens, error) {
	if isValid, err := tp.VerifyToken(refreshToken); isValid && err == nil {
		accessToken, err := tp.GenerateAccess(user)
		if err != nil {
			return nil, err
		}

		return &Tokens{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}, nil
	} else if err != nil {
		return nil, err
	}
	return nil, nil
}

func (tp *JwtTokenProvider) DeleteToken(refreshToken string) error {
	token, err := jwt.ParseWithClaims(refreshToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", token.Header["alg"])
		}
		return tp.secretKey, nil
	})

	if err != nil {
		return err
	}

	userId, err := token.Claims.GetIssuer()
	if err != nil {
		return err
	}

	err = tp.repo.SaveToBlackList(refreshToken, userId)
	if err != nil {
		return fmt.Errorf("error saving token to blacklist: %w", err)
	}
	return nil
}
