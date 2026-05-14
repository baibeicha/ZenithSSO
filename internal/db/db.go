package db

import (
	"AuthServer/configs"
	"fmt"
	"log/slog"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type DB struct {
	*sqlx.DB
	datasource string
}

func Connect(url, dbname, user, password, sslmode string) (*DB, error) {
	if sslmode == "" {
		sslmode = "disable"
	}

	datasource := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s", user, password, url, dbname, sslmode)
	db, err := sqlx.Open(
		"postgres",
		datasource,
	)

	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &DB{
		DB:         db,
		datasource: datasource,
	}, nil
}

func ConnectSource(source *configs.Datasource) (*DB, error) {
	db, err := Connect(
		source.Url,
		source.DB,
		source.User,
		source.Password,
		source.SslMode,
	)

	if err != nil {
		return nil, fmt.Errorf("error connecting to datasource: %w", err)
	}

	return db, nil
}

func (db *DB) Close() {
	err := db.DB.Close()
	if err != nil {
		slog.Error("error closing db", "err", err)
	}
}
