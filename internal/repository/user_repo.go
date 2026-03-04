package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openSystems/auth-service/internal/model"
)

var ErrNotFound = errors.New("not found")
var ErrEmailTaken = errors.New("email already taken")

type UserRepo struct {
	db *pgxpool.Pool
}

func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, email, hashedPassword string) (*model.User, error) {
	user := &model.User{}
	err := r.db.QueryRow(ctx, `
		INSERT INTO users (email, password)
		VALUES ($1, $2)
		RETURNING id, email, password, is_verified, totp_secret, created_at, updated_at`,
		email, hashedPassword,
	).Scan(
		&user.ID, &user.Email, &user.Password,
		&user.IsVerified, &user.TOTPSecret,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrEmailTaken
		}
		return nil, err
	}
	return user, nil
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	user := &model.User{}
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password, is_verified, totp_secret, created_at, updated_at
		FROM users WHERE email = $1`, email,
	).Scan(
		&user.ID, &user.Email, &user.Password,
		&user.IsVerified, &user.TOTPSecret,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return user, err
}

func (r *UserRepo) FindByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	user := &model.User{}
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password, is_verified, totp_secret, created_at, updated_at
		FROM users WHERE id = $1`, id,
	).Scan(
		&user.ID, &user.Email, &user.Password,
		&user.IsVerified, &user.TOTPSecret,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return user, err
}

func (r *UserRepo) MarkVerified(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE users SET is_verified = TRUE, updated_at = NOW() WHERE id = $1`, id)
	return err
}
