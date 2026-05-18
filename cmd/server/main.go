package main

import (
	"AuthServer/api"
	"AuthServer/config"
	"AuthServer/internal"
	"AuthServer/internal/db"
	"AuthServer/internal/jwt"
	"AuthServer/internal/rest"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.MustLoad("config")

	datasource := config.NewDatasourceFromConfig(cfg)
	DB, err := db.ConnectSource(datasource)
	if err != nil {
		slog.Error("Error while connecting to database", "err", err)
		return
	}
	defer DB.Close()

	if err := DB.RunMigrations(); err != nil {
		slog.Error("Error migrating database", "err", err)
		return
	}

	ttlUnit := jwt.GetTimeUnit(cfg.GetString("jwt.ttl.unit"))
	accessTTL := cfg.GetDuration("jwt.ttl.access") * ttlUnit
	refreshTTL := cfg.GetDuration("jwt.ttl.refresh") * ttlUnit

	tokensRepository := jwt.NewTokensRepository(DB, refreshTTL)

	tokenProvider, err := jwt.NewJwtTokenProvider(cfg, tokensRepository, accessTTL, refreshTTL)
	if err != nil {
		slog.Error("Error loading JWT token provider", "err", err)
		return
	}

	cleanupIntervalUnit := jwt.GetTimeUnit(cfg.GetString("jwt.cleanup.unit"))
	cleanupInterval := cfg.GetDuration("jwt.cleanup.interval") * cleanupIntervalUnit
	go jwt.StartTokenCleanup(ctx, tokensRepository, cleanupInterval)

	issuer := cfg.GetString("sso.issuer")
	if issuer == "" {
		issuer = cfg.SSO.Issuer
	}

	authService := internal.NewAuthServer(DB, tokenProvider, slog.Default(), issuer)

	suCfg, cansel := context.WithTimeout(ctx, 5*time.Second)
	if err := authService.SetUpSuperuser(suCfg, cfg); err != nil {
		slog.Error("Error creating superuser", "err", err)
		return
	}
	defer cansel()

	r := chi.NewRouter()

	customUIDir := cfg.GetString("ui.custom_dir")

	authHandler := rest.NewAuthHandler(authService, cfg.GetBool("server.secured"), issuer, customUIDir)
	authHandler.RegisterRoutes(r, customUIDir)

	httpPort := cfg.GetInt("server.port")
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", httpPort),
		Handler: r,
	}

	go func() {
		slog.Info(fmt.Sprintf("Starting HTTP server on port %d", httpPort))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Failed to serve HTTP", "err", err)
		}
	}()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))
	if err != nil {
		slog.Error("Failed to listen", "err", err)
		return
	}
	defer listener.Close()

	var opts []grpc.ServerOption

	if cfg.GRPC.TLS.Enabled {
		creds, err := credentials.NewServerTLSFromFile(cfg.GRPC.TLS.CertPath, cfg.GRPC.TLS.KeyPath)
		if err != nil {
			slog.Error("Failed to setup TLS", "err", err)
			return
		}
		opts = append(opts, grpc.Creds(creds))
		slog.Info("gRPC server is starting in SECURE mode (TLS enabled)")
	} else {
		slog.Info("gRPC server is starting in INSECURE mode (plaintext)")
	}

	server := grpc.NewServer(opts...)

	api.RegisterAuthServiceServer(server, authService)

	go func() {
		<-ctx.Done()
		slog.Info("Shutting down gRPC server gracefully...")
		server.GracefulStop()
	}()

	slog.Info(fmt.Sprintf("Starting gRPC server on port %d", cfg.GRPC.Port))
	if err := server.Serve(listener); err != nil {
		slog.Error("Failed to serve", "err", err)
	}
}
