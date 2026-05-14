package internal

import (
	"AuthServer/api"
	"AuthServer/config"
	"AuthServer/internal/db"
	"AuthServer/internal/encoder"
	"AuthServer/internal/jwt"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

type TokenProvider interface {
	GenerateTokens(user *db.User) (*jwt.Tokens, error)
	VerifyToken(tokenString string) (bool, error)
	RefreshToken(refreshToken string, user *db.User) (*jwt.Tokens, error)
	DeleteToken(refreshToken string) error
}
type AuthServer struct {
	api.UnimplementedAuthServiceServer
	repo          *db.Repository
	tokenProvider TokenProvider
	log           *slog.Logger
}

func NewAuthServer(DB *db.DB, tokenProvider TokenProvider, log *slog.Logger) *AuthServer {
	return &AuthServer{
		repo:          db.NewRepository(DB),
		tokenProvider: tokenProvider,
		log:           log,
	}
}

func (s *AuthServer) SetUpSuperuser(ctx context.Context, cfg *config.Config) error {
	rootWorkspace := "main"
	if s.repo.WorkspaceExists(ctx, rootWorkspace) {
		s.log.Debug("Root workspace exists, no need to register superuser")
		return nil
	}

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

	workspaceId, err := s.repo.CreateWorkspace(ctx, "main")
	if err != nil {
		return fmt.Errorf("error registering workspace '%s': %w", rootWorkspace, err)
	}

	superuserScope := "root"
	superuserScopeId, err := s.repo.CreateScope(ctx, superuserScope, workspaceId)
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

	s.log.Debug("Successfully registered superuser '%s'", superuserUsername)
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

	tokens, err := s.tokenProvider.GenerateTokens(user)
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
