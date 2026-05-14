package main

import (
	"AuthServer/api"
	"AuthServer/config"
	"AuthServer/internal"
	"AuthServer/internal/db"
	"AuthServer/internal/jwt"
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
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

	ttlUnit := jwt.GetTtlUnit(cfg.GetString("jwt.ttl.unit"))
	accessTTL := cfg.GetDuration("jwt.ttl.access") * ttlUnit
	refreshTTL := cfg.GetDuration("jwt.ttl.refresh") * ttlUnit

	tokensRepository := jwt.NewTokensRepository(DB, refreshTTL)

	tokenProvider, err := jwt.NewJwtTokenProvider(cfg, tokensRepository, accessTTL, refreshTTL)
	if err != nil {
		slog.Error("Error loading JWT token provider", "err", err)
		return
	}

	authService := internal.NewAuthServer(DB, tokenProvider, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(5)*time.Second)
	defer cancel()
	if err := authService.SetUpSuperuser(ctx, cfg); err != nil {
		slog.Error("Error creating superuser", "err", err)
		return
	}

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

	slog.Info(fmt.Sprintf("Starting gRPC server on port %d", cfg.GRPC.Port))

	if err := server.Serve(listener); err != nil {
		slog.Error("Failed to serve", "err", err)
	}
}
