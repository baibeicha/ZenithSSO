package jwt

import (
	"AuthServer/internal/db"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenRepository interface {
	IsTokenValid(tokenString string) bool
	SaveToWhiteList(tokenString, userID string, clientID string, ipAddress string, userAgent string) error
	RevokeToken(tokenString string) error
	CleanExpiredTokens(ctx context.Context) error
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token,omitempty"`
}

type TokenClaims struct {
	Username      string `json:"username"`
	Scopes        string `json:"scopes,omitempty"`
	AllowedScopes string `json:"allowed_scopes,omitempty"`
	jwt.RegisteredClaims
}

func (tp *JwtTokenProvider) GenerateAccess(user *db.User, clientID, allowedScopes string) (string, error) {
	var scopes string
	if allowedScopes != "" {
		scopes = user.Scopes.StringFromAllowed(allowedScopes)
	} else {
		scopes = user.Scopes.String()
	}

	claims := TokenClaims{
		Username: user.Username,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strconv.FormatUint(user.ID, 10),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tp.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tp.privateKey)
}

func (tp *JwtTokenProvider) GenerateRefresh(user *db.User, clientID, allowedScopes string) (string, error) {
	claims := TokenClaims{
		Username:      user.Username,
		AllowedScopes: allowedScopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strconv.FormatUint(user.ID, 10),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tp.refreshTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tp.privateKey)
}

func (tp *JwtTokenProvider) GenerateIdToken(user *db.User, clientID string, scopes string, nonce string, issuer string) (string, error) {
	claims := jwt.MapClaims{
		"iss":  issuer,
		"sub":  strconv.FormatUint(user.ID, 10),
		"aud":  clientID,
		"exp":  time.Now().Add(tp.accessTTL).Unix(),
		"iat":  time.Now().Unix(),
		"name": user.Username,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	hasEmail := false
	hasProfile := false
	for _, scope := range strings.Split(scopes, " ") {
		if scope == "email" {
			hasEmail = true
		} else if scope == "profile" {
			hasProfile = true
		}
	}

	if hasEmail {
		claims["email"] = user.Email
	}

	if hasProfile {
		if user.FirstName != nil {
			claims["given_name"] = *user.FirstName
		}
		if user.LastName != nil {
			claims["family_name"] = *user.LastName
		}
		if user.AvatarURL != nil {
			claims["picture"] = *user.AvatarURL
		}
		if user.Locale != nil {
			claims["locale"] = *user.Locale
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tp.privateKey)
}

func (tp *JwtTokenProvider) GenerateTokens(user *db.User, clientID, scopes string, ipAddress, userAgent string) (*Tokens, error) {
	accessToken, err := tp.GenerateAccess(user, clientID, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := tp.GenerateRefresh(user, clientID, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Add the generated refresh token to the whitelist
	err = tp.repo.SaveToWhiteList(refreshToken, strconv.FormatUint(user.ID, 10), clientID, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token to whitelist: %w", err)
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

	if !tp.repo.IsTokenValid(tokenString) {
		return false, errors.New("token is not valid or has been revoked")
	}

	return token.Valid, nil
}

func (tp *JwtTokenProvider) RefreshToken(refreshToken string, user *db.User, clientID string, ipAddress, userAgent string) (*Tokens, error) {
	isValid, err := tp.VerifyToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	if !isValid {
		return nil, errors.New("refresh token is not valid")
	}

	var claims TokenClaims
	_, err = jwt.ParseWithClaims(refreshToken, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signature algorithm: %v", t.Header["alg"])
		}
		return tp.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Verify the refresh token was issued to this client
	if len(claims.Audience) == 0 || claims.Audience[0] != clientID {
		return nil, fmt.Errorf("refresh token was not issued to this client")
	}

	// Invalidate old token (Revoke)
	_ = tp.repo.RevokeToken(refreshToken)

	// Generate a completely new set of tokens (rolling refresh token)
	return tp.GenerateTokens(user, clientID, claims.AllowedScopes, ipAddress, userAgent)
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

	err = tp.repo.RevokeToken(refreshToken)
	if err != nil {
		return fmt.Errorf("error revoking token: %w", err)
	}

	return nil
}

func (tp *JwtTokenProvider) GenerateSessionToken(user *db.User) (string, error) {
	claims := TokenClaims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strconv.FormatUint(user.ID, 10),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(tp.privateKey)
}
