package repository

import (
	"AuthServer/internal/domain"
	"context"
	"log/slog"
)

type UserRepository struct {
	db *DB
}

func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(ctx context.Context, u *domain.User) (uint64, error) {
	var id uint64
	query := `
		INSERT INTO users (username, email, password) 
		VALUES ($1, $2, $3) 
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query, u.Username, u.Email, u.Password).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (r *UserRepository) UserExistsByUsername(ctx context.Context, username string) (bool, error) {
	result := make([]bool, 1)
	err := r.db.Select(&result, "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", username)

	if err != nil {
		slog.Error("error checking user exists", "err", err)
		return false, err
	}

	if len(result) == 0 {
		return false, nil
	}

	return result[0], nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT 
			u.id, 
			u.username, 
			u.email, 
			u.password,
			u.first_name,
			u.last_name,
			u.avatar_url,
			u.locale,
			COALESCE(
				jsonb_agg(
					jsonb_build_object(
						'id', s.id, 
						'name', s.name 
					)
				) FILTER (WHERE s.id IS NOT NULL), '[]'
			) as scopes
		FROM users u
		LEFT JOIN user_scopes us ON u.id = us.user_id
		LEFT JOIN scopes s ON us.scope_id = s.id
		WHERE u.email = $1
		GROUP BY u.id
	`
	var user domain.User
	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT 
			u.id, 
			u.username, 
			u.email, 
			u.password,
			u.first_name,
			u.last_name,
			u.avatar_url,
			u.locale,
			COALESCE(
				jsonb_agg(
					jsonb_build_object(
						'id', s.id, 
						'name', s.name 
					)
				) FILTER (WHERE s.id IS NOT NULL), '[]'
			) as scopes
		FROM users u
		LEFT JOIN user_scopes us ON u.id = us.user_id
		LEFT JOIN scopes s ON us.scope_id = s.id
		WHERE u.username = $1
		GROUP BY u.id
	`
	var user domain.User
	err := r.db.GetContext(ctx, &user, query, username)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, u *domain.User) error {
	query := `
		UPDATE users 
		SET username = :username, email = :email, password = :password 
		WHERE id = :id
	`
	_, err := r.db.NamedExecContext(ctx, query, u)
	return err
}

func (r *UserRepository) UpdateUserProfile(ctx context.Context, u *domain.User) error {
	query := `
		UPDATE users
		SET first_name = :first_name, last_name = :last_name, avatar_url = :avatar_url, locale = :locale
		WHERE id = :id
	`
	_, err := r.db.NamedExecContext(ctx, query, u)
	return err
}

func (r *UserRepository) DeleteUser(ctx context.Context, id uint64) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *UserRepository) CreateScope(ctx context.Context, name string, description string) (uint64, error) {
	var id uint64
	query := `INSERT INTO scopes (name, description) VALUES ($1, $2) RETURNING id`

	err := r.db.QueryRowContext(ctx, query, name, description).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (r *UserRepository) DeleteScope(ctx context.Context, id uint64) error {
	query := `DELETE FROM scopes WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *UserRepository) AddScopeToUser(ctx context.Context, userID, scopeID uint64) error {
	query := `
		INSERT INTO user_scopes (user_id, scope_id) 
		VALUES ($1, $2) 
		ON CONFLICT (user_id, scope_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, userID, scopeID)
	return err
}

func (r *UserRepository) RemoveScopeFromUser(ctx context.Context, userID, scopeID uint64) error {
	query := `DELETE FROM user_scopes WHERE user_id = $1 AND scope_id = $2`
	_, err := r.db.ExecContext(ctx, query, userID, scopeID)
	return err
}

func (r *UserRepository) GetAllUsers(ctx context.Context) ([]domain.User, error) {
	query := `
		SELECT
			u.id,
			u.username,
			u.email,
			u.password,
			u.first_name,
			u.last_name,
			u.avatar_url,
			u.locale,
			COALESCE(
				jsonb_agg(
					jsonb_build_object(
						'id', s.id,
						'name', s.name
					)
				) FILTER (WHERE s.id IS NOT NULL), '[]'
			) as scopes
		FROM users u
		LEFT JOIN user_scopes us ON u.id = us.user_id
		LEFT JOIN scopes s ON us.scope_id = s.id
		GROUP BY u.id
		ORDER BY u.id ASC
	`
	var users []domain.User
	err := r.db.SelectContext(ctx, &users, query)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (r *UserRepository) GetAllScopes(ctx context.Context) ([]domain.Scope, error) {
	query := `SELECT id, name, COALESCE(description, '') as description FROM scopes ORDER BY id ASC`
	var scopes []domain.Scope
	err := r.db.SelectContext(ctx, &scopes, query)
	if err != nil {
		return nil, err
	}
	return scopes, nil
}

func (r *UserRepository) GetUserById(ctx context.Context, userID uint64) (*domain.User, error) {
	query := `
		SELECT 
			u.id, 
			u.username, 
			u.email, 
			u.password,
			u.first_name,
			u.last_name,
			u.avatar_url,
			u.locale,
			COALESCE(
				jsonb_agg(
					jsonb_build_object(
						'id', s.id, 
						'name', s.name 
					)
				) FILTER (WHERE s.id IS NOT NULL), '[]'
			) as scopes
		FROM users u
		LEFT JOIN user_scopes us ON u.id = us.user_id
		LEFT JOIN scopes s ON us.scope_id = s.id
		WHERE u.id = $1
		GROUP BY u.id
	`
	var user domain.User
	err := r.db.GetContext(ctx, &user, query, userID)
	if err != nil {
		return nil, err
	}
	return &user, nil
}
