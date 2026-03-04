package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openSystems/auth-service/internal/model"
)

type SessionRepo struct {
	db *pgxpool.Pool
}

func NewSessionRepo(db *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{db: db}
}

func (r *SessionRepo) Create(ctx context.Context, s *model.Session) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, refresh_token, user_agent, ip, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		s.ID, s.UserID, s.RefreshToken, s.UserAgent, s.IP, s.ExpiresAt,
	)
	return err
}

func (r *SessionRepo) FindByRefreshToken(ctx context.Context, token string) (*model.Session, error) {
	s := &model.Session{}
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, refresh_token, user_agent, ip, expires_at, created_at
		FROM sessions WHERE refresh_token = $1`, token,
	).Scan(&s.ID, &s.UserID, &s.RefreshToken, &s.UserAgent, &s.IP, &s.ExpiresAt, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

func (r *SessionRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]model.Session, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, refresh_token, user_agent, ip, expires_at, created_at
		FROM sessions
		WHERE user_id = $1 AND expires_at > $2
		ORDER BY created_at DESC`,
		userID, time.Now(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []model.Session
	for rows.Next() {
		var s model.Session
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.RefreshToken,
			&s.UserAgent, &s.IP, &s.ExpiresAt, &s.CreatedAt,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (r *SessionRepo) DeleteByID(ctx context.Context, id, userID uuid.UUID) error {
	result, err := r.db.Exec(ctx,
		`DELETE FROM sessions WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *SessionRepo) DeleteByRefreshToken(ctx context.Context, token string) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM sessions WHERE refresh_token = $1`, token)
	return err
}

// RotateRefreshToken заменяет старый refresh token на новый (атомарно).
func (r *SessionRepo) RotateRefreshToken(ctx context.Context, oldToken, newToken string, newExpiry time.Time) error {
	result, err := r.db.Exec(ctx, `
		UPDATE sessions
		SET refresh_token = $1, expires_at = $2
		WHERE refresh_token = $3`,
		newToken, newExpiry, oldToken,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
