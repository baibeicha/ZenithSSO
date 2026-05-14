package db

import (
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func (db *DB) RunMigrations() error {
	dbDriver, err := postgres.WithInstance(db.DB.DB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("error creating database driver: %w", err)
	}

	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("error creating embed migration files: %w", err)
	}

	m, err := migrate.NewWithInstance(
		"iofs",
		sourceDriver,
		"postgres",
		dbDriver,
	)
	if err != nil {
		return fmt.Errorf("error initializing migrate: %w", err)
	}

	err = m.Up()
	if err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			return nil
		}
		return fmt.Errorf("error applying migrations: %w", err)
	}

	return nil
}
