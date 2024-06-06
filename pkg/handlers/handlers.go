package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/reubenmiller/go-c8y/pkg/c8y"
	"github.com/reubenmiller/go-c8y/pkg/microservice"

	"github.com/labstack/echo/v4"
	"github.com/reubenmiller/c8y-token-syner/internal/model"
	"github.com/reubenmiller/c8y-token-syner/pkg/c8yauth"
	certmanager "github.com/reubenmiller/c8y-token-syner/pkg/cert_manager"
	"github.com/reubenmiller/c8y-token-syner/pkg/token"
)

var ApiSharedAuthorization = "/shared/authorization"

// RegisterHandlers registers the http handlers to the given echo server
func RegisterEnrolmentHandlers(e *echo.Echo) {
	e.Add("GET", "/token", GetToken, c8yauth.Authorization(c8yauth.RoleTokenCreate, c8yauth.RoleTokenAdmin))
	e.Add("POST", "/register/:id", RegisterDevice, c8yauth.Authorization(c8yauth.RoleTokenRead, c8yauth.RoleTokenCreate, c8yauth.RoleTokenAdmin))
}

func RegisterSharedAuthHandlers(e *echo.Echo) {
	e.Add("GET", ApiSharedAuthorization, GetSharedCredentials, c8yauth.Authorization(c8yauth.RoleTokenRead))
}

func GetDeviceHMAC(secret string, keys ...string) []byte {
	var values = []string{
		secret,
	}
	values = append(values, keys...)
	return []byte(strings.Join(values, "."))
}

func ExternalIdExists(m *microservice.Microservice, tenant string, externalID string) bool {
	// Check for proof that the external id definitely does NOT exist
	_, extResp, _ := m.Client.Identity.GetExternalID(
		m.WithServiceUser(tenant),
		"c8y_Serial",
		externalID,
	)
	return extResp != nil && extResp.StatusCode() == http.StatusOK
}

func GetSharedCredentials(c echo.Context) error {
	cc := c.(*model.RequestContext)
	authContext, err := c8yauth.GetUserSecurityContext(c)
	if err != nil {
		return err
	}

	user := cc.Microservice.WithServiceUserCredentials(authContext.Tenant)
	authHeader := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s/%s:%s", user.Tenant, user.Username, user.Password)))

	accept := c.Request().Header.Get("Accept")
	switch accept {
	case "plain/text":
		return c.String(http.StatusOK, authHeader)
	default:
		return c.JSON(http.StatusOK, map[string]any{
			"authorization": authHeader,
		})
	}
}

// Check if max number of trusted certificates has been exceeded
func checkMaxCertificates(m *microservice.Microservice, auth c8yauth.AuthContext) (int, error) {
	_, existingCertificates, err := m.Client.DeviceCertificate.GetCertificates(
		m.WithServiceUser(auth.Tenant),
		auth.Tenant,
		&c8y.DeviceCertificateCollectionOptions{
			PaginationOptions: c8y.PaginationOptions{
				PageSize:       1,
				WithTotalPages: true,
			},
		},
	)
	if err != nil {
		return existingCertificates.StatusCode(), &ErrorMessage{
			Err:    "Could not verify number of existing certificates",
			Reason: err.Error(),
		}
	}
	totalCertificates := int64(-1)
	if v := existingCertificates.JSON("statistics.totalPages"); v.Exists() {
		totalCertificates = v.Int()
	}
	maxCertificates := int64(m.Config.GetInt("certificates.max"))
	slog.Info("Device certificate statistics: ", "tenant", auth.Tenant, "total", totalCertificates, "limit", maxCertificates)
	if totalCertificates < 0 || totalCertificates > maxCertificates {
		return http.StatusForbidden, &ErrorMessage{
			Err:    fmt.Sprintf("Total number of trusted certificates exceeded. current=%d, max=%d", totalCertificates, maxCertificates),
			Reason: fmt.Sprintf("The enrolment service is limited to the enrolment of %d (certificate based) devices", maxCertificates),
		}
	}
	return 0, nil
}

// GetDeviceByNameHandler returns a managed object by its name
func GetToken(c echo.Context) error {
	cc := c.(*model.RequestContext)
	externalID := c.QueryParam("externalId")
	scriptType := c.QueryParam("type")

	auth, err := c8yauth.GetUserSecurityContext(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, ErrorMessage{
			Err:    "invalid user context",
			Reason: err.Error(),
		})
	}

	if statusCode, err := checkMaxCertificates(cc.Microservice, auth); err != nil {
		return c.JSON(statusCode, err)
	}

	// Check if device is already registered
	if ExternalIdExists(cc.Microservice, auth.Tenant, externalID) {
		return c.JSON(http.StatusConflict, ErrorMessage{
			Err:    "Device is already registered",
			Reason: "The external identity already exists. You can only generate tokens for devices that don't already exist",
		})
	}

	signingKey := GetDeviceHMAC(
		cc.Microservice.Config.GetString("token.secret"),
		auth.Tenant,
		externalID,
	)

	claims := token.Claims{
		ExternalID: externalID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "c8y-trial",
			Subject:   cc.Microservice.MicroserviceHost,
			ID:        "1",
			Audience: []string{
				cc.Microservice.MicroserviceHost,
			},
		},
	}

	stoken, err := token.Generate(claims, signingKey)
	if err != nil {
		return err
	}

	// Get these authorization header from service (used by client for initial authentication)
	sharedCreds := cc.Microservice.Config.GetString("token.sharedCreds")
	if sharedCreds == "" {
		servicePrefix := strings.TrimRight(cc.Microservice.Config.GetString("service.prefix"), "/")
		sharedCredsResp, err := cc.Microservice.Client.SendRequest(
			cc.Microservice.WithServiceUser(auth.Tenant),
			c8y.RequestOptions{
				Method: "GET",
				Path:   servicePrefix + ApiSharedAuthorization,
				Accept: "plain/text",
			},
		)
		if err != nil {
			slog.Error("Could not get microservice secret", "reason", err)
			return c.JSON(http.StatusUnprocessableEntity, ErrorMessage{
				Err:    "Could not get shared secret from microservice",
				Reason: err.Error(),
			})
		}
		sharedCreds = string(sharedCredsResp.Body())
	}
	encodedAuthHeader := base64.StdEncoding.EncodeToString([]byte(sharedCreds))

	tenant, _, err := cc.Microservice.Client.Tenant.GetCurrentTenant(
		cc.Microservice.WithServiceUser(auth.Tenant),
	)
	if err != nil {
		return err
	}

	code := stoken + "#" + encodedAuthHeader
	installScriptDevice := strings.TrimSpace(fmt.Sprintf(`
	wget -O - https://raw.githubusercontent.com/reubenmiller/c8y-token-syner/main/tools/trial-bootstrap | sh -s -- --enrol 'https://%s/service/c8y-token-syner/register/%s' --code '%s'
	`, tenant.DomainName, externalID, code))

	installScriptDocker := strings.TrimSpace(fmt.Sprintf(`
	wget -O - https://raw.githubusercontent.com/reubenmiller/c8y-token-syner/main/tools/trial-bootstrap-docker | sh -s -- --enrol 'https://%s/service/c8y-token-syner/register/%s' --code '%s'
	`, tenant.DomainName, externalID, code))

	switch scriptType {
	case "docker":
		return c.String(http.StatusCreated, installScriptDocker)
	case "device":
		return c.String(http.StatusCreated, installScriptDevice)
	default:
		return c.JSON(http.StatusCreated, map[string]string{
			"token":  stoken,
			"script": installScriptDevice,
			"docker": installScriptDocker,
		})
	}
}

type ErrorMessage struct {
	Err    string `json:"error"`
	Reason string `json:"reason"`
}

func (e *ErrorMessage) Error() string {
	return e.Err
}

func RegisterDevice(c echo.Context) error {
	cc := c.(*model.RequestContext)
	externalID := c.Param("id")
	var requestToken string

	// Allow reading value from either form["token"], or form["object"]["token"]
	if v := c.FormValue("token"); v != "" {
		requestToken = v
	} else {
		object := c.FormValue("object")
		data := make(map[string]string)
		err := json.Unmarshal([]byte(object), &data)
		if err != nil {
			return err
		}

		if v, ok := data["token"]; !ok {
			return c.JSON(http.StatusUnprocessableEntity, ErrorMessage{
				Err:    "Token is mandatory",
				Reason: "Registration request did not contain a token",
			})
		} else {
			requestToken = v
		}
	}

	claims := &token.Claims{}
	validatedToken, err := jwt.ParseWithClaims(requestToken, claims, func(tok *jwt.Token) (interface{}, error) {
		// Check alg
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
		}

		// Parse the unverified claims which is used in the secret to verify the token.
		// This removes the need to do an API request based on an unverified token.
		unverifiedParser := jwt.NewParser()
		unverifiedClaims := &token.Claims{}
		unverifiedParser.ParseUnverified(requestToken, unverifiedClaims)

		// If the unverified claim does not match the id used in the signing, then the validation will fail
		secret := GetDeviceHMAC(
			cc.Microservice.Config.GetString("token.secret"),
			cc.Microservice.Client.TenantName,
			unverifiedClaims.ExternalID,
		)
		return secret, nil
	})

	if err != nil {
		slog.Error("Invalid registration token.", "reason", err)
		return c.JSON(http.StatusForbidden, ErrorMessage{
			Err:    "Invalid registration token",
			Reason: "Tip: You can only use a token once and only on devices which don't already exist",
		})
	}

	auth, err := c8yauth.GetUserSecurityContext(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, ErrorMessage{
			Err:    "invalid user context",
			Reason: err.Error(),
		})
	}

	// TODO: Do we need to check again if the device has been created by someone else
	// since the token was issued?
	if ExternalIdExists(cc.Microservice, auth.Tenant, externalID) {
		return c.JSON(http.StatusConflict, ErrorMessage{
			Err:    "Device is already registered",
			Reason: "The external identity already exists. You can only generate tokens for devices that don't already exist",
		})
	}

	// Read certificate
	publicCert, err := c.FormFile("file")
	if err != nil {
		return err
	}

	publicCertFile, err := publicCert.Open()
	if err != nil {
		slog.Error("Failed to open public certificate", "reason", err)
		return err
	}
	defer publicCertFile.Close()

	var certBuf strings.Builder
	if _, err := io.Copy(&certBuf, publicCertFile); err != nil {
		slog.Error("Failed to read public certificate", "reason", err)
		return c.JSON(http.StatusUnprocessableEntity, ErrorMessage{
			Err:    "Failed to read certificate",
			Reason: err.Error(),
		})
	}

	deviceCert, err := certmanager.ParseCertificate(certBuf.String())
	if err != nil {
		slog.Error("Invalid certificate", "reason", err)
		return c.JSON(http.StatusUnprocessableEntity, ErrorMessage{
			Err:    "Invalid certificate",
			Reason: err.Error(),
		})
	}

	if claims.ExternalID != deviceCert.Subject.CommonName {
		slog.Error("Certificate does not match the token")
		return c.JSON(http.StatusForbidden, map[string]any{
			"error":  "Certificate Common Name and token mismatch",
			"reason": "The certificate's Common Name (CN) does not match the token",
		})
	}

	// Add trusted certificate
	// With auto registration disabled as it will be registered via the bulk reg api (TODO: does not provide any value)
	cert, certResp, err := cc.Microservice.Client.DeviceCertificate.Create(
		cc.Microservice.WithServiceUser(auth.Tenant),
		auth.Tenant,
		&c8y.Certificate{
			Name:                    externalID,
			AutoRegistrationEnabled: false,
			Status:                  "ENABLED",
			CertInPemFormat:         certBuf.String(),
		},
	)

	if err != nil {
		if certResp != nil && certResp.StatusCode() == http.StatusConflict {
			slog.Info("Trusted certificate has already been uploaded")
			// ignore error
		} else {
			slog.Error("Failed to upload trusted certificate", "reason", err)
			return err
		}
	}

	// Bulk register the device
	bulkRegistrationBody := `"ID","AUTH_TYPE","TYPE","NAME","com_cumulocity_model_Agent.active","PATH"` + "\n" +
		`"` + externalID + `",CERTIFICATES,thin-edge.io,"` + externalID + `",true,"` + "fleet_mgmt" + `"`

	formData := map[string]io.Reader{
		"file": strings.NewReader(bulkRegistrationBody),
	}

	resp, err := cc.Microservice.Client.SendRequest(
		cc.Microservice.WithServiceUser(auth.Tenant),
		c8y.RequestOptions{
			Path:     "devicecontrol/bulkNewDeviceRequests",
			Method:   http.MethodPost,
			Accept:   "application/json",
			FormData: formData,
		},
	)
	if err != nil {
		slog.Error("Failed to register device via bulk registration API", "reason", err)
		return c.JSON(http.StatusForbidden, ErrorMessage{
			Err:    "Failed to register device",
			Reason: err.Error(),
		})
	}
	slog.Info("Registered device successfully", "response", resp)

	return c.JSON(http.StatusCreated, map[string]any{
		"status":             "OK",
		"valid":              validatedToken.Valid,
		"trustedCertificate": cert,
		"claims":             claims,
	})
}
