package handler

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/openSystems/auth-service/internal/service"
)


// ProfileProxy — обратный прокси для ProfileService.
// AuthService выполняет роль API Gateway: проверяет JWT, генерирует
// внутренний токен с claim "sub" и пробрасывает запрос дальше.
type ProfileProxy struct {
	svc   *service.AuthService
	proxy *httputil.ReverseProxy
}

func NewProfileProxy(svc *service.AuthService, profileServiceURL string) (*ProfileProxy, error) {
	target, err := url.Parse(profileServiceURL)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("profile proxy error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"profile service unavailable"}`))
	}

	return &ProfileProxy{svc: svc, proxy: rp}, nil
}

// RegisterRoutes монтирует проксируемые маршруты ProfileService.
// Все запросы к /api/v1/profile/* защищены AuthMiddleware.
func (p *ProfileProxy) RegisterRoutes(r *gin.Engine) {
	profile := r.Group("/api/v1/profile", AuthMiddleware(p.svc))
	profile.Any("/*path", p.forward)
}

func (p *ProfileProxy) forward(c *gin.Context) {
	userID := mustUserID(c)

	c.Request.Header.Del("Authorization")
	c.Request.Header.Set("X-User-ID", userID.String())

	p.proxy.ServeHTTP(c.Writer, c.Request)
}
