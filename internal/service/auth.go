package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/openSystems/auth-service/internal/cache"
	"github.com/openSystems/auth-service/internal/config"
	"github.com/openSystems/auth-service/internal/model"
	"github.com/openSystems/auth-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// ProfileCreator — интерфейс для создания профиля в ProfileService.
type ProfileCreator interface {
	CreateProfile(ctx context.Context, userID string) error
}

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrInvalidCode        = errors.New("invalid or expired code")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

type AuthService struct {
	users    *repository.UserRepo
	sessions *repository.SessionRepo
	cache    *cache.TokenCache
	cfg      *config.JWTConfig
	profiles ProfileCreator
}

func NewAuthService(
	users *repository.UserRepo,
	sessions *repository.SessionRepo,
	cache *cache.TokenCache,
	cfg *config.JWTConfig,
) *AuthService {
	return &AuthService{users: users, sessions: sessions, cache: cache, cfg: cfg}
}

func (s *AuthService) SetProfileCreator(pc ProfileCreator) {
	s.profiles = pc
}

// ─── Register ────────────────────────────────────────────────────────────────

// Register создаёт пользователя и возвращает 6-значный код подтверждения.
// В реальном проекте код отправляется по email; здесь возвращается в ответе
// (для удобства разработки / тестов).
func (s *AuthService) Register(ctx context.Context, email, password string) (confirmCode string, err error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	_, err = s.users.Create(ctx, email, string(hashed))
	if err != nil {
		return "", err // ErrEmailTaken прокидывается выше
	}

	code, err := generateCode(6)
	if err != nil {
		return "", err
	}

	if err := s.cache.SetEmailCode(ctx, email, code, s.cfg.EmailCodeTTL); err != nil {
		return "", err
	}

	return code, nil
}

// ConfirmEmail верифицирует email по коду.
func (s *AuthService) ConfirmEmail(ctx context.Context, email, code string) error {
	stored, err := s.cache.GetEmailCode(ctx, email)
	if err != nil {
		return ErrInvalidCode
	}
	if stored != code {
		return ErrInvalidCode
	}

	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return err
	}

	if err := s.users.MarkVerified(ctx, user.ID); err != nil {
		return err
	}

	if err := s.cache.DeleteEmailCode(ctx, email); err != nil {
		return err
	}

	// Создаём профиль в ProfileService. Ошибка не фатальна — пользователь уже подтверждён,
	// профиль можно создать повторно при следующем запросе.
	if s.profiles != nil {
		if err := s.profiles.CreateProfile(ctx, user.ID.String()); err != nil {
			fmt.Printf("warn: create profile for %s: %v\n", user.ID, err)
		}
	}

	return nil
}

// ─── Login ────────────────────────────────────────────────────────────────────

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // seconds until access token expires
}

func (s *AuthService) Login(ctx context.Context, email, password, userAgent, ip string) (*TokenPair, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.IsVerified {
		return nil, ErrEmailNotVerified
	}

	return s.createSession(ctx, user, userAgent, ip)
}

// ─── Logout ───────────────────────────────────────────────────────────────────

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.sessions.DeleteByRefreshToken(ctx, refreshToken)
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

func (s *AuthService) Refresh(ctx context.Context, oldRefreshToken, userAgent, ip string) (*TokenPair, error) {
	sess, err := s.sessions.FindByRefreshToken(ctx, oldRefreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.sessions.DeleteByRefreshToken(ctx, oldRefreshToken)
		return nil, ErrInvalidToken
	}

	user, err := s.users.FindByID(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}

	newRefresh, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}
	newExpiry := time.Now().Add(s.cfg.RefreshTTL)

	if err := s.sessions.RotateRefreshToken(ctx, oldRefreshToken, newRefresh, newExpiry); err != nil {
		return nil, ErrInvalidToken
	}

	accessToken, err := s.generateAccessToken(user.ID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
		ExpiresIn:    int64(s.cfg.AccessTTL.Seconds()),
	}, nil
}

// ─── Sessions ─────────────────────────────────────────────────────────────────

func (s *AuthService) GetSessions(ctx context.Context, userID uuid.UUID) ([]model.Session, error) {
	return s.sessions.ListByUser(ctx, userID)
}

func (s *AuthService) RevokeSession(ctx context.Context, sessionID, userID uuid.UUID) error {
	err := s.sessions.DeleteByID(ctx, sessionID, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return repository.ErrNotFound
	}
	return err
}

// ─── JWT ──────────────────────────────────────────────────────────────────────

type Claims struct {
	jwt.RegisteredClaims
	UserID uuid.UUID `json:"uid"`
}

func (s *AuthService) ParseAccessToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.cfg.AccessSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func (s *AuthService) createSession(ctx context.Context, user *model.User, userAgent, ip string) (*TokenPair, error) {
	accessToken, err := s.generateAccessToken(user.ID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}

	sess := &model.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		RefreshToken: refreshToken,
		UserAgent:    userAgent,
		IP:           ip,
		ExpiresAt:    time.Now().Add(s.cfg.RefreshTTL),
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.cfg.AccessTTL.Seconds()),
	}, nil
}

func (s *AuthService) generateAccessToken(userID uuid.UUID) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.AccessTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID: userID,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.AccessSecret))
}

// GenerateInternalToken создаёт внутренний JWT для межсервисной коммуникации.
// Использует стандартный claim "sub" = userID, понятный другим сервисам.
func (s *AuthService) GenerateInternalToken(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID.String(),
		"exp": time.Now().Add(s.cfg.AccessTTL).Unix(),
		"iat": time.Now().Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.cfg.AccessSecret))
}

// generateRefreshToken генерирует 256-битный hex-токен.
func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// generateCode генерирует n-значный цифровой код.
func generateCode(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	num, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, num), nil
}
