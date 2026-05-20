package usecase

import (
	"AuthServer/internal/domain"
	"AuthServer/internal/repository"
	"context"
	"errors"
)

type SessionUsecase struct {
	sessionRepo *repository.SessionsRepository
}

func NewSessionUsecase(sessionRepo *repository.SessionsRepository) *SessionUsecase {
	return &SessionUsecase{
		sessionRepo: sessionRepo,
	}
}

func (s *SessionUsecase) GetUserSessions(ctx context.Context, userID uint64) ([]domain.RefreshToken, error) {
	return s.sessionRepo.GetActiveSessionsByUserID(ctx, userID)
}

func (s *SessionUsecase) RevokeSession(ctx context.Context, userID uint64, tokenToRevoke string) error {
	if tokenToRevoke == "" {
		return errors.New("token cannot be empty")
	}
	return s.sessionRepo.RevokeSessionToken(ctx, tokenToRevoke, userID)
}

func (s *SessionUsecase) RevokeAllExceptCurrent(ctx context.Context, userID uint64, currentToken string) error {
	if currentToken == "" {
		return errors.New("current token cannot be empty")
	}
	return s.sessionRepo.RevokeAllSessionsExcept(ctx, userID, currentToken)
}
