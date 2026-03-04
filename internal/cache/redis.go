package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenCache хранит короткоживущие коды и токены в Redis.
type TokenCache struct {
	rdb *redis.Client
}

func NewTokenCache(rdb *redis.Client) *TokenCache {
	return &TokenCache{rdb: rdb}
}

// SetEmailCode сохраняет код подтверждения email (ключ: email_confirm:{email}).
func (c *TokenCache) SetEmailCode(ctx context.Context, email, code string, ttl time.Duration) error {
	return c.rdb.Set(ctx, emailConfirmKey(email), code, ttl).Err()
}

// GetEmailCode возвращает код подтверждения.  Ошибка redis.Nil — код не найден / истёк.
func (c *TokenCache) GetEmailCode(ctx context.Context, email string) (string, error) {
	return c.rdb.Get(ctx, emailConfirmKey(email)).Result()
}

// DeleteEmailCode удаляет код после успешного подтверждения.
func (c *TokenCache) DeleteEmailCode(ctx context.Context, email string) error {
	return c.rdb.Del(ctx, emailConfirmKey(email)).Err()
}

// SetPasswordResetCode сохраняет код сброса пароля.
func (c *TokenCache) SetPasswordResetCode(ctx context.Context, email, code string, ttl time.Duration) error {
	return c.rdb.Set(ctx, passwordResetKey(email), code, ttl).Err()
}

func (c *TokenCache) GetPasswordResetCode(ctx context.Context, email string) (string, error) {
	return c.rdb.Get(ctx, passwordResetKey(email)).Result()
}

func (c *TokenCache) DeletePasswordResetCode(ctx context.Context, email string) error {
	return c.rdb.Del(ctx, passwordResetKey(email)).Err()
}

func emailConfirmKey(email string) string {
	return fmt.Sprintf("email_confirm:%s", email)
}

func passwordResetKey(email string) string {
	return fmt.Sprintf("password_reset:%s", email)
}
