package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openSystems/auth-service/internal/model"
	"github.com/openSystems/auth-service/internal/repository"
	"github.com/openSystems/auth-service/internal/service"
)

// ─── Mock authService ─────────────────────────────────────────────────────────
// Повторяет методы, которые вызывает хендлер.
// Добавь интерфейс authService в handler.go и замени *service.AuthService,
// по той же схеме что делали для ProfileService.

type mockAuthService struct {
	register         func(ctx context.Context, email, password string) (string, error)
	confirmEmail     func(ctx context.Context, email, code string) error
	login            func(ctx context.Context, email, password, userAgent, ip string) (*service.TokenPair, error)
	logout           func(ctx context.Context, refreshToken string) error
	refresh          func(ctx context.Context, oldRefreshToken, userAgent, ip string) (*service.TokenPair, error)
	getSessions      func(ctx context.Context, userID uuid.UUID) ([]model.Session, error)
	revokeSession    func(ctx context.Context, sessionID, userID uuid.UUID) error
	parseAccessToken func(tokenStr string) (*service.Claims, error)
}

func (m *mockAuthService) Register(ctx context.Context, email, password string) (string, error) {
	return m.register(ctx, email, password)
}
func (m *mockAuthService) ConfirmEmail(ctx context.Context, email, code string) error {
	return m.confirmEmail(ctx, email, code)
}
func (m *mockAuthService) Login(ctx context.Context, email, password, userAgent, ip string) (*service.TokenPair, error) {
	return m.login(ctx, email, password, userAgent, ip)
}
func (m *mockAuthService) Logout(ctx context.Context, refreshToken string) error {
	return m.logout(ctx, refreshToken)
}
func (m *mockAuthService) Refresh(ctx context.Context, oldRefreshToken, userAgent, ip string) (*service.TokenPair, error) {
	return m.refresh(ctx, oldRefreshToken, userAgent, ip)
}
func (m *mockAuthService) GetSessions(ctx context.Context, userID uuid.UUID) ([]model.Session, error) {
	return m.getSessions(ctx, userID)
}
func (m *mockAuthService) RevokeSession(ctx context.Context, sessionID, userID uuid.UUID) error {
	return m.revokeSession(ctx, sessionID, userID)
}
func (m *mockAuthService) ParseAccessToken(tokenStr string) (*service.Claims, error) {
	if m.parseAccessToken != nil {
		return m.parseAccessToken(tokenStr)
	}
	return nil, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func init() {
	gin.SetMode(gin.TestMode)
}

// newRouter создаёт роутер с хендлером без реального AuthMiddleware.
// Для защищённых роутов userID кладётся в контекст вручную через withUserID.
func newRouter(svc *mockAuthService) *gin.Engine {
	r := gin.New()
	h := &AuthHandler{svc: svc}

	v1 := r.Group("/api/v1/auth")
	v1.POST("/register", h.Register)
	v1.POST("/register/confirm", h.ConfirmEmail)
	v1.POST("/login", h.Login)
	v1.POST("/refresh", h.Refresh)

	// Защищённые роуты — middleware заменяем заглушкой, которая кладёт userID из хедера X-Test-UserID.
	authed := v1.Group("", testAuthMiddleware())
	authed.POST("/logout", h.Logout)
	authed.GET("/sessions", h.GetSessions)
	authed.DELETE("/sessions/:id", h.RevokeSession)

	return r
}

// testAuthMiddleware эмулирует AuthMiddleware: читает userID из заголовка X-Test-UserID.
func testAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader("X-Test-UserID")
		if raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		id, err := uuid.Parse(raw)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad user id"})
			return
		}
		c.Set(userIDKey, id)
		c.Next()
	}
}

func jsonBody(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

func do(r *gin.Engine, method, path string, body *bytes.Reader, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, body)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func tokenPairFixture() *service.TokenPair {
	return &service.TokenPair{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresIn:    3600,
	}
}

// ─── Register ─────────────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	svc := &mockAuthService{
		register: func(_ context.Context, email, password string) (string, error) {
			assert.Equal(t, "user@example.com", email)
			assert.Equal(t, "password123", password)
			return "123456", nil
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register",
		jsonBody(t, map[string]string{"email": "user@example.com", "password": "password123"}),
		nil,
	)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "123456", resp["confirm_code"])
}

func TestRegister_InvalidEmail_Returns400(t *testing.T) {
	svc := &mockAuthService{}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register",
		jsonBody(t, map[string]string{"email": "not-an-email", "password": "password123"}),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegister_ShortPassword_Returns400(t *testing.T) {
	svc := &mockAuthService{}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register",
		jsonBody(t, map[string]string{"email": "user@example.com", "password": "short"}),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegister_EmailTaken_Returns409(t *testing.T) {
	svc := &mockAuthService{
		register: func(_ context.Context, _, _ string) (string, error) {
			return "", repository.ErrEmailTaken
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register",
		jsonBody(t, map[string]string{"email": "taken@example.com", "password": "password123"}),
		nil,
	)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestRegister_UCError_Returns500(t *testing.T) {
	svc := &mockAuthService{
		register: func(_ context.Context, _, _ string) (string, error) {
			return "", errors.New("db error")
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register",
		jsonBody(t, map[string]string{"email": "user@example.com", "password": "password123"}),
		nil,
	)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ─── ConfirmEmail ─────────────────────────────────────────────────────────────

func TestConfirmEmail_Success(t *testing.T) {
	svc := &mockAuthService{
		confirmEmail: func(_ context.Context, email, code string) error {
			assert.Equal(t, "user@example.com", email)
			assert.Equal(t, "123456", code)
			return nil
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register/confirm",
		jsonBody(t, map[string]string{"email": "user@example.com", "code": "123456"}),
		nil,
	)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestConfirmEmail_InvalidCode_Returns422(t *testing.T) {
	svc := &mockAuthService{
		confirmEmail: func(_ context.Context, _, _ string) error {
			return service.ErrInvalidCode
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register/confirm",
		jsonBody(t, map[string]string{"email": "user@example.com", "code": "000000"}),
		nil,
	)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestConfirmEmail_WrongCodeLength_Returns400(t *testing.T) {
	// binding:"len=6" — код должен быть ровно 6 символов
	svc := &mockAuthService{}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register/confirm",
		jsonBody(t, map[string]string{"email": "user@example.com", "code": "12345"}),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestConfirmEmail_UCError_Returns500(t *testing.T) {
	svc := &mockAuthService{
		confirmEmail: func(_ context.Context, _, _ string) error {
			return errors.New("db error")
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/register/confirm",
		jsonBody(t, map[string]string{"email": "user@example.com", "code": "123456"}),
		nil,
	)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ─── Login ────────────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	pair := tokenPairFixture()
	svc := &mockAuthService{
		login: func(_ context.Context, email, password, _, _ string) (*service.TokenPair, error) {
			assert.Equal(t, "user@example.com", email)
			assert.Equal(t, "password123", password)
			return pair, nil
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": "user@example.com", "password": "password123"}),
		nil,
	)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, pair.AccessToken, resp["access_token"])
	assert.Equal(t, pair.RefreshToken, resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
}

func TestLogin_InvalidCredentials_Returns401(t *testing.T) {
	svc := &mockAuthService{
		login: func(_ context.Context, _, _, _, _ string) (*service.TokenPair, error) {
			return nil, service.ErrInvalidCredentials
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": "user@example.com", "password": "wrong"}),
		nil,
	)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_EmailNotVerified_Returns403(t *testing.T) {
	svc := &mockAuthService{
		login: func(_ context.Context, _, _, _, _ string) (*service.TokenPair, error) {
			return nil, service.ErrEmailNotVerified
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": "user@example.com", "password": "password123"}),
		nil,
	)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestLogin_UCError_Returns500(t *testing.T) {
	svc := &mockAuthService{
		login: func(_ context.Context, _, _, _, _ string) (*service.TokenPair, error) {
			return nil, errors.New("db error")
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/login",
		jsonBody(t, map[string]string{"email": "user@example.com", "password": "password123"}),
		nil,
	)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

func TestRefresh_Success(t *testing.T) {
	pair := tokenPairFixture()
	svc := &mockAuthService{
		refresh: func(_ context.Context, oldToken, _, _ string) (*service.TokenPair, error) {
			assert.Equal(t, "old-refresh-token", oldToken)
			return pair, nil
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/refresh",
		jsonBody(t, map[string]string{"refresh_token": "old-refresh-token"}),
		nil,
	)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, pair.AccessToken, resp["access_token"])
}

func TestRefresh_InvalidToken_Returns401(t *testing.T) {
	svc := &mockAuthService{
		refresh: func(_ context.Context, _, _, _ string) (*service.TokenPair, error) {
			return nil, service.ErrInvalidToken
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/refresh",
		jsonBody(t, map[string]string{"refresh_token": "expired"}),
		nil,
	)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefresh_MissingToken_Returns400(t *testing.T) {
	svc := &mockAuthService{}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/refresh",
		jsonBody(t, map[string]any{}), // refresh_token отсутствует
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ─── Logout ───────────────────────────────────────────────────────────────────

func TestLogout_Success(t *testing.T) {
	testUserID := uuid.New()
	svc := &mockAuthService{
		logout: func(_ context.Context, refreshToken string) error {
			assert.Equal(t, "refresh-token", refreshToken)
			return nil
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/logout",
		jsonBody(t, map[string]string{"refresh_token": "refresh-token"}),
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogout_UCError_Returns500(t *testing.T) {
	testUserID := uuid.New()
	svc := &mockAuthService{
		logout: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}

	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/logout",
		jsonBody(t, map[string]string{"refresh_token": "refresh-token"}),
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLogout_Unauthorized_Returns401(t *testing.T) {
	svc := &mockAuthService{}

	// X-Test-UserID не передан → testAuthMiddleware вернёт 401
	w := do(newRouter(svc), http.MethodPost, "/api/v1/auth/logout",
		jsonBody(t, map[string]string{"refresh_token": "refresh-token"}),
		nil,
	)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ─── GetSessions ──────────────────────────────────────────────────────────────

func TestGetSessions_Success(t *testing.T) {
	testUserID := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	sessions := []model.Session{
		{
			ID:        uuid.New(),
			UserID:    testUserID,
			UserAgent: "Mozilla/5.0",
			IP:        "127.0.0.1",
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now,
		},
	}
	svc := &mockAuthService{
		getSessions: func(_ context.Context, userID uuid.UUID) ([]model.Session, error) {
			assert.Equal(t, testUserID, userID)
			return sessions, nil
		},
	}

	w := do(newRouter(svc), http.MethodGet, "/api/v1/auth/sessions",
		nil,
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	list, ok := resp["sessions"].([]any)
	require.True(t, ok)
	assert.Len(t, list, 1)

	first := list[0].(map[string]any)
	assert.Equal(t, sessions[0].ID.String(), first["id"])
	assert.Equal(t, "Mozilla/5.0", first["user_agent"])
	assert.Equal(t, "127.0.0.1", first["ip"])
}

func TestGetSessions_UCError_Returns500(t *testing.T) {
	testUserID := uuid.New()
	svc := &mockAuthService{
		getSessions: func(_ context.Context, _ uuid.UUID) ([]model.Session, error) {
			return nil, errors.New("db error")
		},
	}

	w := do(newRouter(svc), http.MethodGet, "/api/v1/auth/sessions",
		nil,
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ─── RevokeSession ────────────────────────────────────────────────────────────

func TestRevokeSession_Success(t *testing.T) {
	testUserID := uuid.New()
	sessionID := uuid.New()
	svc := &mockAuthService{
		revokeSession: func(_ context.Context, sID, uID uuid.UUID) error {
			assert.Equal(t, sessionID, sID)
			assert.Equal(t, testUserID, uID)
			return nil
		},
	}

	w := do(newRouter(svc), http.MethodDelete, "/api/v1/auth/sessions/"+sessionID.String(),
		nil,
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevokeSession_InvalidUUID_Returns400(t *testing.T) {
	testUserID := uuid.New()
	svc := &mockAuthService{}

	w := do(newRouter(svc), http.MethodDelete, "/api/v1/auth/sessions/not-a-uuid",
		nil,
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeSession_NotFound_Returns404(t *testing.T) {
	testUserID := uuid.New()
	sessionID := uuid.New()
	svc := &mockAuthService{
		revokeSession: func(_ context.Context, _, _ uuid.UUID) error {
			return repository.ErrNotFound
		},
	}

	w := do(newRouter(svc), http.MethodDelete, "/api/v1/auth/sessions/"+sessionID.String(),
		nil,
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRevokeSession_UCError_Returns500(t *testing.T) {
	testUserID := uuid.New()
	sessionID := uuid.New()
	svc := &mockAuthService{
		revokeSession: func(_ context.Context, _, _ uuid.UUID) error {
			return errors.New("db error")
		},
	}

	w := do(newRouter(svc), http.MethodDelete, "/api/v1/auth/sessions/"+sessionID.String(),
		nil,
		map[string]string{"X-Test-UserID": testUserID.String()},
	)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
