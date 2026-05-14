package internal

import (
	"AuthServer/api"
	"AuthServer/config"
	"AuthServer/internal/db"
	"AuthServer/internal/encoder"
	"AuthServer/internal/jwt"
	"AuthServer/internal/utils"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

type TokenProvider interface {
	GenerateTokens(user *db.User, scopes string) (*jwt.Tokens, error)
	GenerateIdToken(user *db.User, clientID string, scopes string) (string, error)
	GenerateSessionToken(user *db.User) (string, error)
	VerifyToken(tokenString string) (bool, error)
	RefreshToken(refreshToken string, user *db.User) (*jwt.Tokens, error)
	DeleteToken(refreshToken string) error
	GetPublicJWKS() jwt.JWKS
	GetClaims(tokenString string) (*jwt.TokenClaims, error)
}

type AuthServer struct {
	api.UnimplementedAuthServiceServer
	repo          *db.Repository
	ClientsRepo   *db.ClientsRepository
	AuthCodesRepo *db.AuthCodesRepository
	tokenProvider TokenProvider
	log           *slog.Logger
}

func NewAuthServer(DB *db.DB, tokenProvider TokenProvider, log *slog.Logger) *AuthServer {
	return &AuthServer{
		repo:          db.NewRepository(DB),
		ClientsRepo:   db.NewClientsRepository(DB),
		AuthCodesRepo: db.NewAuthCodesRepository(DB),
		tokenProvider: tokenProvider,
		log:           log,
	}
}

func (s *AuthServer) ValidateUser(ctx context.Context, username, password string) (*db.User, error) {
	user, err := s.repo.GetUserByUsername(ctx, username)
	if user == nil || err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !encoder.CheckPasswordHash(password, user.Password) {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

func (s *AuthServer) CreateSessionToken(user *db.User) (string, error) {
	return s.tokenProvider.GenerateSessionToken(user)
}

func (s *AuthServer) GenerateAuthorizationCodeForUser(ctx context.Context, userID uint64, clientID, redirectURI, codeChallenge, codeChallengeMethod, requestedScopes string) (string, error) {
	client, err := s.ClientsRepo.GetClientByID(ctx, clientID)
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

	authCode := &db.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scopes:              requestedScopes,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	err = s.AuthCodesRepo.SaveCode(ctx, authCode)
	if err != nil {
		return "", err
	}

	return code, nil
}

func (s *AuthServer) RefreshTokens(ctx context.Context, refreshToken string) (*jwt.Tokens, error) {
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

	user, err := s.repo.GetUserById(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	return s.tokenProvider.RefreshToken(refreshToken, user)
}

func (s *AuthServer) GenerateAuthorizationCode(ctx context.Context, username, password, clientID, redirectURI, codeChallenge, codeChallengeMethod string) (string, error) {
	user, err := s.repo.GetUserByUsername(ctx, username)
	if user == nil || err != nil {
		return "", errors.New("invalid credentials")
	}

	if !encoder.CheckPasswordHash(password, user.Password) {
		return "", errors.New("invalid credentials")
	}

	_, err = s.ClientsRepo.GetClientByID(ctx, clientID)
	if err != nil {
		return "", errors.New("invalid client_id")
	}

	code, err := utils.GenerateAuthCode()
	if err != nil {
		return "", err
	}

	authCode := &db.AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              user.ID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
	}

	err = s.AuthCodesRepo.SaveCode(ctx, authCode)
	if err != nil {
		return "", err
	}

	return code, nil
}

func (s *AuthServer) ExchangeAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (*jwt.Tokens, error) {
	authCode, err := s.AuthCodesRepo.GetAndDeleteCode(ctx, code)
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

	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	if authCode.CodeChallenge != expectedChallenge {
		return nil, errors.New("invalid code_verifier")
	}

	user, err := s.repo.GetUserById(ctx, authCode.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	tokens, err := s.tokenProvider.GenerateTokens(user, authCode.Scopes)
	if err != nil {
		return nil, err
	}

	idToken, err := s.tokenProvider.GenerateIdToken(user, clientID, authCode.Scopes)
	if err != nil {
		return nil, err
	}

	tokens.IdToken = idToken

	return tokens, nil
}

func (s *AuthServer) SetUpSuperuser(ctx context.Context, cfg *config.Config) error {
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

	if exists, err := s.repo.UserExistsByUsername(ctx, superuserUsername); err != nil || exists {
		if err != nil {
			return fmt.Errorf("error checking if user %s exists: %w", superuserUsername, err)
		}

		s.log.Info(fmt.Sprintf("superuser %s already exists", superuserUsername))
		return nil
	}

	superuserScope := "root"
	superuserScopeId, err := s.repo.CreateScope(ctx, superuserScope)
	if err != nil {
		return fmt.Errorf("error registering scope '%s': %w", superuserScope, err)
	}

	superuserPassword, err := encoder.HashPassword(superuserPasswordRaw)
	if err != nil {
		return fmt.Errorf("error creating superuser '%s': %w", superuserScope, err)
	}

	user := &db.User{
		Username: superuserUsername,
		Email:    superuserEmail,
		Password: superuserPassword,
	}

	userId, err := s.repo.CreateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("error registering superuser: %w", err)
	}

	if err := s.repo.AddScopeToUser(ctx, userId, superuserScopeId); err != nil {
		return fmt.Errorf("error adding scope to superuser '%s': %w", superuserScope, err)
	}

	s.log.Info(fmt.Sprintf("Successfully registered superuser '%s'", superuserUsername))
	return nil
}

func (s *AuthServer) Register(ctx context.Context, request *api.RegisterRequest) (*api.Status, error) {
	if u, err := s.repo.GetUserByUsername(ctx, request.GetUsername()); u != nil || err != nil {
		if u != nil {
			return &api.Status{
				Status:  false,
				Message: new(fmt.Sprintf("user '%s' already exists", request.GetUsername())),
			}, nil
		}

		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

	hash, err := encoder.HashPassword(request.GetPassword())
	if err != nil {
		return nil, err
	}

	user := &db.User{
		Username: request.GetUsername(),
		Email:    request.GetEmail(),
		Password: hash,
	}

	if _, err = s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	return &api.Status{Status: true}, nil
}

func (s *AuthServer) Login(ctx context.Context, request *api.AuthRequest) (*api.AuthResponse, error) {
	user, err := s.repo.GetUserByUsername(ctx, request.GetUsername())
	if user == nil || err != nil {
		if user == nil {
			return nil, fmt.Errorf("user '%s' not found", request.GetUsername())
		}

		return nil, err
	}

	if !encoder.CheckPasswordHash(request.GetPassword(), user.Password) {
		return nil, fmt.Errorf("invalid password")
	}

	tokens, err := s.tokenProvider.GenerateTokens(user, "")
	if err != nil {
		return nil, err
	}

	return &api.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *AuthServer) Validate(ctx context.Context, token *api.Token) (*api.Status, error) {
	isValid, err := s.tokenProvider.VerifyToken(token.GetToken())
	if err != nil {
		return nil, err
	}

	return &api.Status{Status: isValid}, nil
}

func (s *AuthServer) Logout(ctx context.Context, token *api.Token) (*api.Status, error) {
	err := s.tokenProvider.DeleteToken(token.GetToken())
	if err != nil {
		return nil, err
	}

	return &api.Status{Status: true}, nil
}

func (s *AuthServer) GetUserInfo(ctx context.Context, accessToken string) (*db.User, error) {
	claims, err := s.tokenProvider.GetClaims(accessToken)
	if err != nil {
		return nil, err
	}

	userID, _ := claims.GetIssuer()
	id, _ := strconv.ParseUint(userID, 10, 64)

	return s.repo.GetUserById(ctx, id)
}

func (s *AuthServer) GetJWKS() jwt.JWKS {
	return s.tokenProvider.GetPublicJWKS()
}
