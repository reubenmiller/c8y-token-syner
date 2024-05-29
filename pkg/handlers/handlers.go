package handlers

import (
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
	certmanager "github.com/reubenmiller/c8y-token-syner/pkg/cert_manager"
	"github.com/reubenmiller/c8y-token-syner/pkg/token"
)

// RegisterHandlers registers the http handlers to the given echo server
func RegisterHandlers(e *echo.Echo) {
	e.Add("GET", "/token", GetToken)
	e.Add("POST", "/register/:id", RegisterDevice)
}

func GetDeviceHMAC(secret string, keys ...string) []byte {
	var values = []string{
		secret,
	}
	values = append(values, keys...)
	return []byte(strings.Join(values, "."))
}

func ExternalIdExists(m *microservice.Microservice, externalID string) bool {
	// Check for proof that the external id definitely does NOT exist
	_, extResp, _ := m.Client.Identity.GetExternalID(
		m.WithServiceUser(),
		"c8y_Serial",
		externalID,
	)
	return extResp != nil && extResp.StatusCode() == http.StatusOK
}

// GetDeviceByNameHandler returns a managed object by its name
func GetToken(c echo.Context) error {
	cc := c.(*model.RequestContext)
	externalID := c.QueryParam("externalId")
	scriptType := c.QueryParam("type")

	// Check if device is already registered
	if ExternalIdExists(cc.Microservice, externalID) {
		return c.JSON(http.StatusConflict, ErrorMessage{
			Error:  "Device is already registered",
			Reason: "The external identity already exists. You can only generate tokens for devices that don't already exist",
		})
	}

	signingKey := GetDeviceHMAC(
		cc.Microservice.Config.GetString("token.secret"),
		cc.Microservice.Client.TenantName,
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

	// TODO: Get these credentials from the microservice via the application api tenant/username:password
	sharedCreds := cc.Microservice.Config.GetString("token.sharedCreds")
	tenant, _, err := cc.Microservice.Client.Tenant.GetCurrentTenant(
		cc.Microservice.WithServiceUser(),
	)
	if err != nil {
		return err
	}

	code := stoken + "#" + sharedCreds
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
	Error  string `json:"error"`
	Reason string `json:"reason"`
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
				Error:  "Token is mandatory",
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
			Error:  "Invalid registration token",
			Reason: "Tip: You can only use a token once and only on devices which don't already exist",
		})
	}

	// TODO: Do we need to check again if the device has been created by someone else
	// since the token was issued?
	if ExternalIdExists(cc.Microservice, externalID) {
		return c.JSON(http.StatusConflict, ErrorMessage{
			Error:  "Device is already registered",
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
			Error:  "Failed to read certificate",
			Reason: err.Error(),
		})
	}

	deviceCert, err := certmanager.ParseCertificate(certBuf.String())
	if err != nil {
		slog.Error("Invalid certificate", "reason", err)
		return c.JSON(http.StatusUnprocessableEntity, ErrorMessage{
			Error:  "Invalid certificate",
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
		cc.Microservice.WithServiceUser(),
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
	bulkRegistrationBody := `"ID","AUTH_TYPE","TYPE","NAME","com_cumulocity_model_Agent.active"` + "\n" +
		`"` + externalID + `",CERTIFICATES,thin-edge.io,"` + externalID + `",true`

	formData := map[string]io.Reader{
		"file": strings.NewReader(bulkRegistrationBody),
	}

	resp, err := cc.Microservice.Client.SendRequest(
		cc.Microservice.WithServiceUser(),
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
			Error:  "Failed to register device",
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
