package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openSystems/auth-service/internal/repository"
	"github.com/openSystems/auth-service/internal/service"
)

type AuthHandler struct {
	svc *service.AuthService
}

func NewAuthHandler(svc *service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// RegisterRoutes монтирует все роуты Auth Service.
func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	v1 := r.Group("/api/v1/auth")
	{
		v1.POST("/register", h.Register)
		v1.POST("/register/confirm", h.ConfirmEmail)
		v1.POST("/login", h.Login)
		v1.POST("/refresh", h.Refresh)

		authed := v1.Group("", AuthMiddleware(h.svc))
		{
			authed.POST("/logout", h.Logout)
			authed.GET("/sessions", h.GetSessions)
			authed.DELETE("/sessions/:id", h.RevokeSession)
		}
	}
}

// ─── POST /api/v1/auth/register ──────────────────────────────────────────────

type registerRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	code, err := h.svc.Register(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, repository.ErrEmailTaken) {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// В production код отправляется на почту. Здесь возвращаем для удобства разработки.
	c.JSON(http.StatusCreated, gin.H{
		"message":      "registration successful, check your email",
		"confirm_code": code, // убрать в production
	})
}

// ─── POST /api/v1/auth/register/confirm ──────────────────────────────────────

type confirmRequest struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code"  binding:"required,len=6"`
}

func (h *AuthHandler) ConfirmEmail(c *gin.Context) {
	var req confirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.ConfirmEmail(c.Request.Context(), req.Email, req.Code); err != nil {
		if errors.Is(err, service.ErrInvalidCode) {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid or expired code"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "email confirmed"})
}

// ─── POST /api/v1/auth/login ──────────────────────────────────────────────────

type loginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	pair, err := h.svc.Login(c.Request.Context(), req.Email, req.Password, userAgent, ip)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		case errors.Is(err, service.ErrEmailNotVerified):
			c.JSON(http.StatusForbidden, gin.H{"error": "email not verified"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"expires_in":    pair.ExpiresIn,
		"token_type":    "Bearer",
	})
}

// ─── POST /api/v1/auth/logout (AUTH) ─────────────────────────────────────────

type logoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req logoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// ─── POST /api/v1/auth/refresh ────────────────────────────────────────────────

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	pair, err := h.svc.Refresh(c.Request.Context(), req.RefreshToken, userAgent, ip)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  pair.AccessToken,
		"refresh_token": pair.RefreshToken,
		"expires_in":    pair.ExpiresIn,
		"token_type":    "Bearer",
	})
}

// ─── GET /api/v1/auth/sessions (AUTH) ────────────────────────────────────────

func (h *AuthHandler) GetSessions(c *gin.Context) {
	userID := mustUserID(c)

	sessions, err := h.svc.GetSessions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	type sessionView struct {
		ID        string `json:"id"`
		UserAgent string `json:"user_agent"`
		IP        string `json:"ip"`
		ExpiresAt string `json:"expires_at"`
		CreatedAt string `json:"created_at"`
	}

	views := make([]sessionView, 0, len(sessions))
	for _, s := range sessions {
		views = append(views, sessionView{
			ID:        s.ID.String(),
			UserAgent: s.UserAgent,
			IP:        s.IP,
			ExpiresAt: s.ExpiresAt.Format("2006-01-02T15:04:05Z"),
			CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	c.JSON(http.StatusOK, gin.H{"sessions": views})
}

// ─── DELETE /api/v1/auth/sessions/:id (AUTH) ─────────────────────────────────

func (h *AuthHandler) RevokeSession(c *gin.Context) {
	userID := mustUserID(c)

	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session id"})
		return
	}

	if err := h.svc.RevokeSession(c.Request.Context(), sessionID, userID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "session revoked"})
}
