package usecase

import (
	"AuthServer/config"
	"AuthServer/internal/domain"
	"AuthServer/internal/encoder"
	"AuthServer/internal/jwt"
	"AuthServer/internal/repository"
	"AuthServer/internal/utils"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

type AuthUsecase struct {
	userRepo      *repository.UserRepository
	clientRepo    *repository.ClientsRepository
	authCodesRepo *repository.AuthCodesRepository
	tokenProvider *jwt.JwtTokenProvider
	log           *slog.Logger
	issuer        string
}

func NewAuthUsecase(userRepo *repository.UserRepository, clientRepo *repository.ClientsRepository, authCodesRepo *repository.AuthCodesRepository, tokenProvider *jwt.JwtTokenProvider, log *slog.Logger, issuer string) *AuthUsecase {
	return &AuthUsecase{
		userRepo:      userRepo,
		clientRepo:    clientRepo,
		authCodesRepo: authCodesRepo,
		tokenProvider: tokenProvider,
		log:           log,
		issuer:        issuer,
	}
}

func (s *AuthUsecase) ValidateUser(ctx context.Context, username, password string) (*domain.User, error) {
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if user == nil || err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !encoder.CheckPasswordHash(password, user.Password) {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

func (s *AuthUsecase) CreateSessionToken(user *domain.User, ipAddress, userAgent string) (string, error) {
	return s.tokenProvider.GenerateSessionToken(user, ipAddress, userAgent)
}

func (s *AuthUsecase) GenerateAuthorizationCodeForUser(ctx context.Context, userID uint64, clientID, redirectURI, codeChallenge, codeChallengeMethod, requestedScopes, nonce string) (string, error) {
	client, err := s.clientRepo.GetClientByID(ctx, clientID)
	if err != nil {
		return "", errors.New("invalid client_id")
	}

	var allowedURIs []string
	if err := json.Unmarshal(client.RedirectURIs, &allowedURIs); err != nil {
		return "", errors.New("invalid client configuration")
	}

	validURI := false
	for _, uri := range allowedURIs {
		if uri == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		return "", errors.New("invalid redirect_uri")
	}

	var allowedScopes []string
	if err := json.Unmarshal(client.AllowedScopes, &allowedScopes); err != nil {
		return "", errors.New("invalid client scope config")
	}

	reqScopesList := strings.Split(requestedScopes, " ")
	for _, rs := range reqScopesList {
		if rs == "" {
			continue
		}
		found := false
		for _, as := range allowedScopes {
			if rs == as {
				found = true
				break
			}
		}
		if !found && rs != "" {
			return "", fmt.Errorf("scope '%s' is not allowed for this client", rs)
		}
	}

	code, err := utils.GenerateAuthCode()
	if err != nil {
		return "", err
	}

	authCode := &domain.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scopes:              requestedScopes,
		Nonce:               nonce,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	err = s.authCodesRepo.SaveCode(ctx, authCode)
	if err != nil {
		return "", err
	}

	return code, nil
}

func (s *AuthUsecase) RefreshTokens(ctx context.Context, refreshToken string, clientID string, ipAddress string, userAgent string) (*jwt.Tokens, error) {
	claims, err := s.tokenProvider.GetClaims(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	userIDStr, err := claims.GetIssuer()
	if err != nil || userIDStr == "" {
		return nil, errors.New("invalid token claims")
	}

	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		return nil, errors.New("invalid user id in token")
	}

	user, err := s.userRepo.GetUserById(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	return s.tokenProvider.RefreshToken(refreshToken, user, clientID, ipAddress, userAgent)
}

func (s *AuthUsecase) ExchangeAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string, ipAddress string, userAgent string) (*jwt.Tokens, error) {
	authCode, err := s.authCodesRepo.GetAndDeleteCode(ctx, code)
	if err != nil {
		return nil, errors.New("invalid or expired authorization code")
	}

	if authCode.ClientID != clientID {
		return nil, errors.New("invalid client_id")
	}

	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("invalid redirect_uri")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.New("authorization code expired")
	}

	var expectedChallenge string
	if authCode.CodeChallengeMethod == "S256" {
		hasher := sha256.New()
		hasher.Write([]byte(codeVerifier))
		expectedChallenge = base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	} else if authCode.CodeChallengeMethod == "plain" {
		expectedChallenge = codeVerifier
	} else {
		return nil, errors.New("unsupported code_challenge_method")
	}

	if authCode.CodeChallenge != expectedChallenge {
		return nil, errors.New("invalid code_verifier")
	}

	user, err := s.userRepo.GetUserById(ctx, authCode.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	tokens, err := s.tokenProvider.GenerateTokens(user, clientID, authCode.Scopes, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	hasOpenid := false
	for _, scope := range strings.Split(authCode.Scopes, " ") {
		if scope == "openid" {
			hasOpenid = true
			break
		}
	}

	if hasOpenid {
		idToken, err := s.tokenProvider.GenerateIdToken(user, clientID, authCode.Scopes, authCode.Nonce, s.issuer)
		if err != nil {
			return nil, err
		}
		tokens.IdToken = idToken
	}

	return tokens, nil
}

func (s *AuthUsecase) SetUpSuperuser(ctx context.Context, cfg *config.Config) error {
	superuserUsername := cfg.GetString("superuser.username")
	if superuserUsername == "" {
		return errors.New("superuser username is empty")
	}
	superuserEmail := cfg.GetString("superuser.email")
	if superuserEmail == "" {
		return errors.New("superuser email is empty")
	}

	superuserPasswordRaw := cfg.GetString("superuser.password")
	if superuserPasswordRaw == "" {
		return errors.New("superuser password is empty")
	}

	if exists, err := s.userRepo.UserExistsByUsername(ctx, superuserUsername); err != nil || exists {
		if err != nil {
			return fmt.Errorf("error checking if user %s exists: %w", superuserUsername, err)
		}

		s.log.Info(fmt.Sprintf("superuser %s already exists", superuserUsername))
		return nil
	}

	superuserScope := "root"
	superuserScopeId, err := s.userRepo.CreateScope(ctx, superuserScope, "Superuser access")
	if err != nil {
		return fmt.Errorf("error registering scope '%s': %w", superuserScope, err)
	}

	superuserPassword, err := encoder.HashPassword(superuserPasswordRaw)
	if err != nil {
		return fmt.Errorf("error creating superuser '%s': %w", superuserScope, err)
	}

	user := &domain.User{
		Username: superuserUsername,
		Email:    superuserEmail,
		Password: superuserPassword,
	}

	userId, err := s.userRepo.CreateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("error registering superuser: %w", err)
	}

	if err := s.userRepo.AddScopeToUser(ctx, userId, superuserScopeId); err != nil {
		return fmt.Errorf("error adding scope to superuser '%s': %w", superuserScope, err)
	}

	s.log.Info(fmt.Sprintf("Successfully registered superuser '%s'", superuserUsername))
	return nil
}

func (s *AuthUsecase) GetAllUsers(ctx context.Context) ([]domain.User, error) {
	return s.userRepo.GetAllUsers(ctx)
}

func (s *AuthUsecase) CreateScope(ctx context.Context, name, description string) (uint64, error) {
	return s.userRepo.CreateScope(ctx, name, description)
}

func (s *AuthUsecase) AssignScopeToUser(ctx context.Context, userID, scopeID uint64) error {
	return s.userRepo.AddScopeToUser(ctx, userID, scopeID)
}

func (s *AuthUsecase) GetAllScopes(ctx context.Context) ([]domain.Scope, error) {
	return s.userRepo.GetAllScopes(ctx)
}

func (s *AuthUsecase) GetUserInfo(ctx context.Context, accessToken string) (*domain.User, error) {
	claims, err := s.tokenProvider.GetClaims(accessToken)
	if err != nil {
		return nil, err
	}

	userID, _ := claims.GetIssuer()
	id, _ := strconv.ParseUint(userID, 10, 64)

	return s.userRepo.GetUserById(ctx, id)
}

func (s *AuthUsecase) UpdateUserProfile(ctx context.Context, user *domain.User) error {
	return s.userRepo.UpdateUserProfile(ctx, user)
}

func (s *AuthUsecase) GetJWKS() jwt.JWKS {
	return s.tokenProvider.GetPublicJWKS()
}

func (s *AuthUsecase) RevokeToken(ctx context.Context, token string) error {
	return s.tokenProvider.DeleteToken(token)
}

func (s *AuthUsecase) Register(ctx context.Context, username, email, password string) error {
	if u, err := s.userRepo.GetUserByUsername(ctx, username); u != nil || err != nil {
		if u != nil {
			return fmt.Errorf("user '%s' already exists", username)
		}
	}

	hash, err := encoder.HashPassword(password)
	if err != nil {
		return err
	}

	user := &domain.User{
		Username: username,
		Email:    email,
		Password: hash,
	}

	if _, err = s.userRepo.CreateUser(ctx, user); err != nil {
		return err
	}

	return nil
}

func (s *AuthUsecase) Login(ctx context.Context, username, password string) (*jwt.Tokens, error) {
	user, err := s.userRepo.GetUserByUsername(ctx, username)
	if user == nil || err != nil {
		if user == nil {
			return nil, fmt.Errorf("user '%s' not found", username)
		}

		return nil, err
	}

	if !encoder.CheckPasswordHash(password, user.Password) {
		return nil, fmt.Errorf("invalid password")
	}

	tokens, err := s.tokenProvider.GenerateTokens(user, "", "", "", "")
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func (s *AuthUsecase) GetClientByID(ctx context.Context, clientID string) (*domain.Client, error) {
	return s.clientRepo.GetClientByID(ctx, clientID)
}
