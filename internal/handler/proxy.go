package handler

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openSystems/auth-service/internal/service"
)

// ProfileProxy — обратный прокси для ProfileService.
// AuthService выполняет роль API Gateway: проверяет JWT и пробрасывает
// запрос дальше с заголовком X-User-ID.
type ProfileProxy struct {
	svc   *service.AuthService
	proxy *httputil.ReverseProxy
}

func NewProfileProxy(svc *service.AuthService, profileServiceURL string) (*ProfileProxy, error) {
	target, err := url.Parse(profileServiceURL)
	if err != nil {
		return nil, err
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// Снимаем префикс /api/v1/profile — ProfileService ожидает /me, /contacts, и т.д.
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/api/v1/profile")
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
			if target.RawPath != "" {
				req.URL.RawPath = strings.TrimPrefix(req.URL.RawPath, "/api/v1/profile")
			}
			req.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("profile proxy error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"profile service unavailable"}`))
		},
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

// MessageProxy — обратный прокси для MessageService.
// Проверяет JWT, снимает префикс /api/v1/messages и пробрасывает запрос
// с заголовком X-User-ID.
type MessageProxy struct {
	svc   *service.AuthService
	proxy *httputil.ReverseProxy
}

func NewMessageProxy(svc *service.AuthService, messageServiceURL string) (*MessageProxy, error) {
	target, err := url.Parse(messageServiceURL)
	if err != nil {
		return nil, err
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// Снимаем префикс /api/v1/messages — MessageService ожидает /chats/, /messages/
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/api/v1/messages")
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
			if target.RawPath != "" {
				req.URL.RawPath = strings.TrimPrefix(req.URL.RawPath, "/api/v1/messages")
			}
			req.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("message proxy error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"message service unavailable"}`))
		},
	}

	return &MessageProxy{svc: svc, proxy: rp}, nil
}

// RegisterRoutes монтирует проксируемые маршруты MessageService.
// Все запросы к /api/v1/messages/* защищены AuthMiddleware.
func (m *MessageProxy) RegisterRoutes(r *gin.Engine) {
	messages := r.Group("/api/v1/messages", AuthMiddleware(m.svc))
	messages.Any("/*path", m.forward)
}

func (m *MessageProxy) forward(c *gin.Context) {
	userID := mustUserID(c)

	c.Request.Header.Del("Authorization")
	c.Request.Header.Set("X-User-ID", userID.String())

	m.proxy.ServeHTTP(c.Writer, c.Request)
}
