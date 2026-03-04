package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTP     HTTPConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Services ServicesConfig
}

type ServicesConfig struct {
	ProfileServiceURL string
}

type HTTPConfig struct {
	Port string
}

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func (p PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.User, p.Password, p.DBName, p.SSLMode,
	)
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type JWTConfig struct {
	AccessSecret  string
	RefreshTTL    time.Duration
	AccessTTL     time.Duration
	EmailCodeTTL  time.Duration
}

func Load() (*Config, error) {
	refreshTTL, err := parseDuration(env("JWT_REFRESH_TTL", "720h")) // 30 дней
	if err != nil {
		return nil, fmt.Errorf("JWT_REFRESH_TTL: %w", err)
	}
	accessTTL, err := parseDuration(env("JWT_ACCESS_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("JWT_ACCESS_TTL: %w", err)
	}
	emailCodeTTL, err := parseDuration(env("EMAIL_CODE_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("EMAIL_CODE_TTL: %w", err)
	}

	redisDB, _ := strconv.Atoi(env("REDIS_DB", "0"))

	return &Config{
		HTTP: HTTPConfig{
			Port: env("HTTP_PORT", "8081"),
		},
		Postgres: PostgresConfig{
			Host:     env("POSTGRES_HOST", "localhost"),
			Port:     env("POSTGRES_PORT", "5432"),
			User:     env("POSTGRES_USER", "postgres"),
			Password: env("POSTGRES_PASSWORD", "postgres"),
			DBName:   env("POSTGRES_DB", "auth"),
			SSLMode:  env("POSTGRES_SSLMODE", "disable"),
		},
		Redis: RedisConfig{
			Addr:     env("REDIS_ADDR", "localhost:6379"),
			Password: env("REDIS_PASSWORD", ""),
			DB:       redisDB,
		},
		JWT: JWTConfig{
			AccessSecret: env("JWT_ACCESS_SECRET", "change-me-in-production"),
			RefreshTTL:   refreshTTL,
			AccessTTL:    accessTTL,
			EmailCodeTTL: emailCodeTTL,
		},
		Services: ServicesConfig{
			ProfileServiceURL: env("PROFILE_SERVICE_URL", "http://localhost:8082"),
		},
	}, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
