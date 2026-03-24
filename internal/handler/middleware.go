package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const userIDKey = "userID"

// AuthMiddleware проверяет JWT из заголовка Authorization: Bearer <token>
// или из query-параметра ?token= (для WebSocket, где заголовки не поддерживаются).
func AuthMiddleware(svc authService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := ""

		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
				return
			}
			tokenString = parts[1]
		} else {
			tokenString = c.Query("token")
			if tokenString == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
				return
			}
		}

		claims, err := svc.ParseAccessToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		c.Set(userIDKey, claims.UserID)
		c.Next()
	}
}

// mustUserID достаёт userID из контекста (паникует только при неверной сборке роутов).
func mustUserID(c *gin.Context) uuid.UUID {
	return c.MustGet(userIDKey).(uuid.UUID)
}
