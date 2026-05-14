package db

import (
	"context"
)

type ClientsRepository struct {
	db *DB
}

func NewClientsRepository(db *DB) *ClientsRepository {
	return &ClientsRepository{db: db}
}

func (r *ClientsRepository) GetClientByID(ctx context.Context, clientID string) (*Client, error) {
	var client Client
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
