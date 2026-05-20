package repository

import (
	"AuthServer/internal/domain"
	"context"
)

type ClientsRepository struct {
	db *DB
}

func NewClientsRepository(db *DB) *ClientsRepository {
	return &ClientsRepository{db: db}
}

func (r *ClientsRepository) GetClientByID(ctx context.Context, clientID string) (*domain.Client, error) {
	var client domain.Client
	query := `
		SELECT id, client_id, client_secret_hash, redirect_uris 
		FROM clients 
		WHERE client_id = $1
	`
	err := r.db.GetContext(ctx, &client, query, clientID)
	if err != nil {
		return nil, err
	}
	return &client, nil
}
