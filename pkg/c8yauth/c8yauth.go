package c8yauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/reubenmiller/go-c8y/pkg/c8y"
	"github.com/tidwall/gjson"
)

type Role string

const (
	RoleTokenRead   Role = "ROLE_TOKEN_TRIAL_REQUEST_READ"
	RoleTokenCreate Role = "ROLE_TOKEN_TRIAL_REQUEST_CREATE"
	RoleTokenAdmin  Role = "ROLE_TOKEN_TRIAL_REQUEST_ADMIN"
)

func Authentication(authProvider *AuthenticationProvider) echo.MiddlewareFunc {
	// values := c.Request().Header.Values(header)
	// return echo
	return middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		KeyLookup:  "header:Authorization",
		AuthScheme: "Basic",
		Validator: func(rawAuth string, c echo.Context) (bool, error) {
			auth, err := base64.StdEncoding.DecodeString(rawAuth)
			if err != nil {
				return false, echo.NewHTTPError(http.StatusUnauthorized, "invalid base64 auth value")
			}
			parts := strings.Split(string(auth), ":")
			if len(parts) != 2 {
				return false, echo.NewHTTPError(http.StatusUnauthorized, "invalid auth")
			}
			sc, ok := authProvider.Authorize(parts[0])
			if !ok {
				return false, echo.NewHTTPError(http.StatusUnauthorized, "invalid auth")
			}
			c.Set(SecurityContextKey, sc)
			return true, nil
		},
	})
}

func AuthenticationBearer(authProvider *AuthenticationProvider) echo.MiddlewareFunc {
	return middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		KeyLookup:  "header:Authorization,cookie:authorization",
		AuthScheme: "Bearer",
		Skipper: func(c echo.Context) bool {
			path := c.Request().URL.Path
			slog.Debug("Middleware: Checking if need to skip path.", "path", path)
			noAuthPaths := []string{
				"/health",
				"/prometheus",
			}
			for _, subpath := range noAuthPaths {
				if subpath == path {
					return true
				}
			}
			return false
		},
		Validator: func(rawAuth string, c echo.Context) (bool, error) {
			sc, ok := authProvider.Authorize(rawAuth)
			if !ok {
				return false, echo.NewHTTPError(http.StatusUnauthorized, "invalid auth")
			}
			c.Set(SecurityContextKey, sc)
			return true, nil
		},
	})
}

type (
	Stats struct {
		Uptime       time.Time      `json:"uptime"`
		RequestCount uint64         `json:"requestCount"`
		Statuses     map[string]int `json:"statuses"`
		mutex        sync.RWMutex
	}
)

func NewStats() *Stats {
	return &Stats{
		Uptime:   time.Now(),
		Statuses: map[string]int{},
	}
}

// Process is the middleware function.
func (s *Stats) Process(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if err := next(c); err != nil {
			c.Error(err)
		}
		s.mutex.Lock()
		defer s.mutex.Unlock()

		userAuth := c.Request().Header.Values("Authorization")
		_ = userAuth

		return nil
	}
}

// AuthContext holds information about user who has been authenticated for request
type AuthContext struct {
	UserID string
	Roles  map[string]struct{}
}

type AuthenticationProvider struct {
	client *c8y.Client
}

func NewAuthProvider(client *c8y.Client) *AuthenticationProvider {
	return &AuthenticationProvider{
		client: client,
	}
}

func NewBearerAuthorizationContext(token string) context.Context {
	return context.WithValue(context.Background(), c8y.GetContextAuthTokenKey(), "Bearer "+token)
}

func (a *AuthenticationProvider) Authorize(token string) (AuthContext, bool) {
	user, userResp, err := a.client.User.GetCurrentUser(
		NewBearerAuthorizationContext(token),
	)
	if err != nil {
		return AuthContext{}, false
	}
	roles := make(map[string]struct{})

	slog.Debug("User roles", "response", userResp.JSON())

	if effectiveRoles := userResp.JSON("effectiveRoles"); effectiveRoles.Exists() {
		effectiveRoles.ForEach(func(key, value gjson.Result) bool {
			roleID := value.Get("id").String()
			if roleID != "" {
				roles[roleID] = struct{}{}
			}
			return true
		})
	}
	// TODO: Use once go-c8y 0.18.0 is released
	// if user.EffectiveRoles != nil {
	// 	for _, r := range user.Roles.References {
	// 		roles[r.Role.ID] = struct{}{}
	// 	}
	// }

	return AuthContext{
		UserID: user.ID,
		Roles:  roles,
	}, true
}

const (
	SecurityContextKey = "__SecurityContextKey__"
)

// Authorization checks if context contains at least one given privilege (OR check) on failure request ends with 401 unauthorized error
func Authorization(roles ...Role) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			raw := c.Get(SecurityContextKey)
			if raw == nil {
				return echo.ErrUnauthorized
			}
			authContext, ok := raw.(AuthContext)
			if !ok {
				return echo.ErrUnauthorized
			}
			if !authContext.CheckPrivilege(roles...) {
				return echo.NewHTTPError(http.StatusUnauthorized, fmt.Sprintf("missing role: %v", roles))
			}
			return next(c)
		}
	}
}

// CheckPrivilege checks if user in AuthContext has at least one (OR) of given privilege
func (s *AuthContext) CheckPrivilege(roles ...Role) bool {
	if len(roles) == 0 {
		return true
	}
	for _, check := range roles {
		if _, found := s.Roles[string(check)]; found {
			return true
		}
	}
	return false
	// for role := range s.Roles {
	// 	for _, check := range roles {
	// 		if role == string(check) {
	// 			return true
	// 		}
	// 	}
	// }
	// return false
}