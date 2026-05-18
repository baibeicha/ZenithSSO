package rest

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"AuthServer/api"
	"AuthServer/internal"
	"AuthServer/internal/encoder"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

type AuthHandler struct {
	authService *internal.AuthServer
	secured     bool
	issuer      string
	templates   *template.Template
}

func NewAuthHandler(as *internal.AuthServer, secured bool, issuer string) *AuthHandler {
	tmpl, _ := template.ParseGlob("web/templates/*.html")
	if tmpl == nil {
		tmpl = template.New("fallback")
	}

	return &AuthHandler{
		authService: as,
		secured:     secured,
		issuer:      issuer,
		templates:   tmpl,
	}
}

func (h *AuthHandler) RegisterRoutes(r chi.Router) {
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/.well-known/openid-configuration", h.DiscoveryHandler)
	r.Get("/api/v1/jwks", h.JwksHandler)
	r.Get("/api/v1/userinfo", h.UserInfoHandler)

	r.Post("/api/v1/register", h.RegisterHandler)
	r.Post("/api/v1/token", h.TokenHandler)
	r.Post("/api/v1/consent", h.ConsentPOSTHandler)

	r.Get("/api/v1/authorize", h.AuthorizeGETHandler)
	r.Post("/api/v1/authorize", h.AuthorizePOSTHandler)
	r.Get("/api/v1/consent", h.ConsentGETHandler)

	r.Get("/api/v1/register", h.RegisterGETHandler)
}

func (h *AuthHandler) RegisterGETHandler(w http.ResponseWriter, r *http.Request) {
	err := h.templates.ExecuteTemplate(w, "register.html", nil)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (h *AuthHandler) DiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuer

	data := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/api/v1/authorize",
		"token_endpoint":                        issuer + "/api/v1/token",
		"userinfo_endpoint":                     issuer + "/api/v1/userinfo",
		"jwks_uri":                              issuer + "/api/v1/jwks",
		"response_types_supported":              []string{"code", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *AuthHandler) JwksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.authService.GetJWKS())
}

func (h *AuthHandler) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	user, err := h.authService.GetUserInfo(r.Context(), token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":      user.ID,
		"name":     user.Username,
		"email":    user.Email,
		"username": user.Username,
	})
}

func (h *AuthHandler) AuthorizeGETHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported_response_type: only 'code' is supported", http.StatusBadRequest)
		return
	}

	clientID := q.Get("client_id")

	_, err := h.authService.ClientsRepo.GetClientByID(r.Context(), clientID)
	if err != nil {
		http.Error(w, "invalid_client: application not found", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("sso_session")
	if err == nil && cookie.Value != "" {
		_, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
		if err == nil {
			consentURL := &url.URL{Path: "/api/v1/consent"}
			consentURL.RawQuery = q.Encode()
			http.Redirect(w, r, consentURL.String(), http.StatusFound)
			return
		}
	}

	data := map[string]interface{}{
		"Error": q.Get("error"),
	}

	err = h.templates.ExecuteTemplate(w, "authorize.html", data)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (h *AuthHandler) AuthorizePOSTHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.authService.ValidateUser(r.Context(), username, password)
	if err != nil {
		loginURL := &url.URL{Path: "/api/v1/authorize"}
		q := r.URL.Query()
		q.Set("error", "invalid_credentials")
		loginURL.RawQuery = q.Encode()
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}

	sessionToken, err := h.authService.CreateSessionToken(user)
	if err == nil {
		http.SetCookie(w, &http.Cookie{
			Name:     "sso_session",
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   h.secured,
			MaxAge:   86400,
			SameSite: http.SameSiteLaxMode,
		})
	}

	consentURL := &url.URL{Path: "/api/v1/consent"}

	params := url.Values{}
	for k, v := range r.Form {
		if k != "username" && k != "password" {
			params[k] = v
		}
	}
	consentURL.RawQuery = params.Encode()

	http.Redirect(w, r, consentURL.String(), http.StatusFound)
}

func (h *AuthHandler) ConsentGETHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sso_session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/api/v1/authorize?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	_, err = h.authService.GetUserInfo(r.Context(), cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/api/v1/authorize?"+r.URL.RawQuery, http.StatusFound)
		return
	}

	err = h.templates.ExecuteTemplate(w, "consent.html", nil)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (h *AuthHandler) ConsentPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request form", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("sso_session")
	if err != nil || cookie.Value == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	scopes := r.FormValue("scope")
	nonce := r.FormValue("nonce")

	code, err := h.authService.GenerateAuthorizationCodeForUser(r.Context(), user.ID, clientID, redirectURI,
		codeChallenge, codeChallengeMethod, scopes, nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, buildRedirectURL(redirectURI, code, state), http.StatusFound)
}

func (h *AuthHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req api.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := h.authService.Register(r.Context(), &req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !resp.Status {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": resp.GetMessage()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "user successfully registered"})
}

func (h *AuthHandler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
		return
	}

	grantType := r.FormValue("grant_type")
	w.Header().Set("Content-Type", "application/json")

	// Helper for Client Authentication
	authenticateClient := func() (string, error) {
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}

		if clientID == "" || clientSecret == "" {
			return "", errors.New("invalid_client")
		}

		client, err := h.authService.ClientsRepo.GetClientByID(r.Context(), clientID)
		if err != nil {
			return "", errors.New("invalid_client")
		}

		// Check client secret using the logic
		if !encoder.CheckPasswordHash(clientSecret, client.ClientSecretHash) {
			return "", errors.New("invalid_client")
		}

		return clientID, nil
	}

	switch grantType {
	case "authorization_code":
		clientID, err := authenticateClient()
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}

		code := r.FormValue("code")
		redirectURI := r.FormValue("redirect_uri")
		codeVerifier := r.FormValue("code_verifier")

		tokens, err := h.authService.ExchangeAuthorizationCode(r.Context(), code, clientID, redirectURI, codeVerifier)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(tokens)

	case "refresh_token":
		clientID, err := authenticateClient()
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}

		refreshToken := r.FormValue("refresh_token")
		if refreshToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
			return
		}

		tokens, err := h.authService.RefreshTokens(r.Context(), refreshToken, clientID)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(tokens)

	case "password", "":
		var req api.AuthRequest
		if r.Header.Get("Content-Type") == "application/json" {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
				return
			}
		} else {
			req.Username = r.FormValue("username")
			req.Password = r.FormValue("password")
		}

		resp, err := h.authService.Login(r.Context(), &req)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(resp)

	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
	}
}

func buildRedirectURL(baseURI, code, state string) string {
	u, err := url.Parse(baseURI)
	if err != nil {
		return baseURI
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}

	u.RawQuery = q.Encode()
	return u.String()
}
