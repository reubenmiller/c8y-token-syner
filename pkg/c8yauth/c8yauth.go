package c8yauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/reubenmiller/go-c8y/pkg/c8y"
)

// ErrInvalidAuthType is error type when the KeyAuth middleware detects and invalid auth type, e.g. Basic vs Bearer
type ErrInvalidAuthType struct {
	Err error
}

// Error returns errors text
func (e *ErrInvalidAuthType) Error() string {
	return e.Err.Error()
}

type Role string

const (
	RoleTokenRead   Role = "ROLE_TOKEN_TRIAL_REQUEST_READ"
	RoleTokenCreate Role = "ROLE_TOKEN_TRIAL_REQUEST_CREATE"
	RoleTokenAdmin  Role = "ROLE_TOKEN_TRIAL_REQUEST_ADMIN"
)

func SkipCheck(c echo.Context) bool {
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
}

func AuthenticationBasic(authProvider *AuthenticationProvider) echo.MiddlewareFunc {
	return middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		KeyLookup:  "header:Authorization,cookie:authorization",
		AuthScheme: "Basic",
		Skipper:    SkipCheck,
		ErrorHandler: func(err error, c echo.Context) error {
			// Allow other middleware to be processed
			if _, ok := err.(*middleware.ErrKeyAuthMissing); ok {
				return nil
			}
			if _, ok := err.(*ErrInvalidAuthType); ok {
				return nil
			}
			return err
		},
		ContinueOnIgnoredError: true,
		Validator: func(rawAuth string, c echo.Context) (bool, error) {
			auth, err := base64.StdEncoding.DecodeString(rawAuth)
			if err != nil {
				return false, &ErrInvalidAuthType{
					Err: err,
				}
			}
			parts := strings.Split(string(auth), ":")
			if len(parts) != 2 {
				return false, echo.NewHTTPError(http.StatusUnauthorized, "invalid auth")
			}

			var ctx context.Context
			if tenant, username, found := strings.Cut(parts[0], "/"); found {
				ctx = NewBasicAuthorizationContext(tenant, username, parts[1])
			} else {
				// TODO: Should the tenant name be provided by the application?
				ctx = NewBasicAuthorizationContext("", parts[0], parts[1])
			}
			sc, ok := authProvider.Authorize(ctx)
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
		Skipper:    SkipCheck,
		ErrorHandler: func(err error, c echo.Context) error {
			// Allow other middleware to be processed
			if _, ok := err.(*middleware.ErrKeyAuthMissing); ok {
				return nil
			}
			return err
		},
		ContinueOnIgnoredError: true,
		Validator: func(rawAuth string, c echo.Context) (bool, error) {
			sc, ok := authProvider.Authorize(NewBearerAuthorizationContext(rawAuth))
			if !ok {
				return false, echo.NewHTTPError(http.StatusUnauthorized, "invalid auth")
			}
			c.Set(SecurityContextKey, sc)
			return true, nil
		},
	})
}

// AuthContext holds information about user who has been authenticated for request
type AuthContext struct {
	UserID string
	Tenant string
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

func NewBasicAuthorizationContext(tenant, username, password string) context.Context {
	var auth string
	if tenant != "" {
		auth = fmt.Sprintf("%s/%s:%s", tenant, username, password)
	} else {
		auth = fmt.Sprintf("%s:%s", username, password)
	}

	return context.WithValue(context.Background(), c8y.GetContextAuthTokenKey(), "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
}

func (a *AuthenticationProvider) Authorize(ctx context.Context) (AuthContext, bool) {
	user, userResp, err := a.client.User.GetCurrentUser(
		ctx,
	)
	if err != nil {
		return AuthContext{}, false
	}
	roles := make(map[string]struct{})

	slog.Debug("User roles", "response", userResp.JSON())
	if user.EffectiveRoles != nil {
		for _, r := range user.EffectiveRoles {
			roles[r.ID] = struct{}{}
		}
	}

	// Get current tenant
	tenant, _, err := a.client.Tenant.GetCurrentTenant(ctx)
	if err != nil {
		slog.Error("Could not get user's current tenant", "reason", err)
		return AuthContext{}, false
	}

	return AuthContext{
		UserID: user.ID,
		Roles:  roles,
		Tenant: tenant.Name,
	}, true
}

const (
	SecurityContextKey = "__SecurityContextKey__"
)

func GetUserSecurityContext(c echo.Context) (AuthContext, error) {
	raw := c.Get(SecurityContextKey)
	if raw == nil {
		return AuthContext{}, echo.ErrUnauthorized
	}
	authContext, ok := raw.(AuthContext)
	if !ok {
		return AuthContext{}, echo.ErrUnauthorized
	}
	return authContext, nil
}

// Authorization checks if context contains at least one given privilege (OR check) on failure request ends with 401 unauthorized error
func Authorization(roles ...Role) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authContext, err := GetUserSecurityContext(c)
			if err != nil {
				return err
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
