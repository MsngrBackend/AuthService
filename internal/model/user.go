package model

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID         uuid.UUID `db:"id"`
	Email      string    `db:"email"`
	Password   string    `db:"password"` // bcrypt hash
	IsVerified bool      `db:"is_verified"`
	TOTPSecret *string   `db:"totp_secret"` // nil = 2FA off
	CreatedAt  time.Time `db:"created_at"`
	UpdatedAt  time.Time `db:"updated_at"`
}
