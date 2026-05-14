package jwt

import (
	"context"
	"log/slog"
	"time"
)

func StartTokenCleanup(ctx context.Context, repo TokenRepository, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("Token cleanup background job started", "interval", interval.String())
	for {
		select {
		case <-ticker.C:
			if err := repo.CleanExpiredTokens(ctx); err != nil {
				slog.Error("Failed to clean expired tokens", "err", err)
			} else {
				slog.Debug("Expired tokens cleaned successfully")
			}
		case <-ctx.Done():
			slog.Info("Token cleanup background job stopped")
			return
		}
	}
}
