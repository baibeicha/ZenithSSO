package main

import (
	"AuthServer/api"
	"AuthServer/configs"
	"AuthServer/internal"
	"AuthServer/internal/db"
	"AuthServer/internal/jwt"
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
)

func main() {
	cfg, err := configs.NewConfig("config")
	if err != nil {
		slog.Error("Error loading config", "err", err)
		return
	}

	datasource := configs.NewDatasourceFromConfig(cfg)
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

	tokenProvider := jwt.NewJwtTokenProvider(cfg, DB)
	authService := internal.NewAuthServer(DB, tokenProvider, slog.Default())

	ctx, cansel := context.WithTimeout(context.Background(), time.Duration(5)*time.Second)
	if err := authService.SetUpSuperuser(ctx, cfg); err != nil {
		slog.Error("Error creating superuser", "err", err)
		return
	}

	grpcServer := grpc.NewServer()
	api.RegisterAuthServiceServer(grpcServer, authService)

	port := cfg.GetServerPort()
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		slog.Error("Error while starting listener", "err", err)
		return
	}
	defer func() {
		err := listener.Close()
		if err != nil {
			slog.Error("Error closing listener", "err", err)
		}
	}()

	defer grpcServer.GracefulStop()
	cansel()
	err = grpcServer.Serve(listener)
	if err != nil {
		slog.Error("Error while starting gRPC server", "err", err)
		return
	}
}
