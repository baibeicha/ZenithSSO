package grpc

import (
	"AuthServer/api"
	"AuthServer/internal/usecase"
	"context"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthHandler struct {
	api.UnimplementedAuthServiceServer
	authUsecase *usecase.AuthUsecase
}

func NewAuthHandler(authUsecase *usecase.AuthUsecase) *AuthHandler {
	return &AuthHandler{
		authUsecase: authUsecase,
	}
}

func (h *AuthHandler) Token(ctx context.Context, req *api.TokenRequest) (*api.TokenResponse, error) {
	if req.GetGrantType() == "authorization_code" {
		tokens, err := h.authUsecase.ExchangeAuthorizationCode(
			ctx,
			req.GetCode(),
			req.GetClientId(),
			req.GetRedirectUri(),
			req.GetCodeVerifier(),
			"grpc-client-ip", // To get real IP we'd use peer from context
			"grpc-client-ua",
		)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid request: %v", err)
		}
		return &api.TokenResponse{
			AccessToken:  tokens.AccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: tokens.RefreshToken,
			IdToken:      tokens.IdToken,
		}, nil
	} else if req.GetGrantType() == "refresh_token" {
		tokens, err := h.authUsecase.RefreshTokens(
			ctx,
			req.GetRefreshToken(),
			req.GetClientId(),
			"grpc-client-ip",
			"grpc-client-ua",
		)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token: %v", err)
		}
		return &api.TokenResponse{
			AccessToken:  tokens.AccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: tokens.RefreshToken,
			IdToken:      tokens.IdToken,
		}, nil
	}
	return nil, status.Errorf(codes.InvalidArgument, "unsupported grant_type")
}

func (h *AuthHandler) Authorize(ctx context.Context, req *api.AuthorizeRequest) (*api.AuthorizeResponse, error) {
	// For gRPC, we implement a headless authorization for trusted clients who can supply username/password
	user, err := h.authUsecase.ValidateUser(ctx, req.GetUsername(), req.GetPassword())
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	code, err := h.authUsecase.GenerateAuthorizationCodeForUser(
		ctx,
		user.ID,
		req.GetClientId(),
		req.GetRedirectUri(),
		req.GetCodeChallenge(),
		req.GetCodeChallengeMethod(),
		req.GetScope(),
		req.GetNonce(),
	)

	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "authorization failed: %v", err)
	}

	return &api.AuthorizeResponse{
		Code:       code,
		State:      req.GetState(),
		RedirectTo: req.GetRedirectUri() + "?code=" + code + "&state=" + req.GetState(),
	}, nil
}

func (h *AuthHandler) UserInfo(ctx context.Context, req *api.UserInfoRequest) (*api.UserInfoResponse, error) {
	user, err := h.authUsecase.GetUserInfo(ctx, req.GetAccessToken())
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	res := &api.UserInfoResponse{
		Sub:   strconv.FormatUint(user.ID, 10),
		Name:  user.Username,
		Email: user.Email,
	}

	if user.FirstName != nil {
		res.GivenName = *user.FirstName
	}
	if user.LastName != nil {
		res.FamilyName = *user.LastName
	}
	if user.AvatarURL != nil {
		res.Picture = *user.AvatarURL
	}
	if user.Locale != nil {
		res.Locale = *user.Locale
	}

	return res, nil
}

func (h *AuthHandler) Revoke(ctx context.Context, req *api.RevokeRequest) (*api.Status, error) {
	err := h.authUsecase.RevokeToken(ctx, req.GetToken())
	if err != nil {
		return &api.Status{Status: false, Message: stringPtr(err.Error())}, nil
	}
	return &api.Status{Status: true}, nil
}

func (h *AuthHandler) Sessions(ctx context.Context, req *api.SessionsRequest) (*api.SessionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Sessions not implemented")
}

func (h *AuthHandler) RevokeSession(ctx context.Context, req *api.RevokeSessionRequest) (*api.Status, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RevokeSession not implemented")
}

func stringPtr(s string) *string {
	return &s
}
