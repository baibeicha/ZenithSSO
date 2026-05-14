package rest

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"AuthServer/api"
	"AuthServer/internal"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

type AuthHandler struct {
	authService *internal.AuthServer
	secured     bool
}

func NewAuthHandler(as *internal.AuthServer, secured bool) *AuthHandler {
	return &AuthHandler{
		authService: as,
		secured:     secured,
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

	r.Get("/api/v1/authorize", h.AuthorizeGETHandler)
	r.Post("/api/v1/authorize", h.AuthorizePOSTHandler)
}

func (h *AuthHandler) DiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	issuer := scheme + "://" + r.Host

	data := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize.html",
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

	cookie, err := r.Cookie("sso_session")
	if err == nil && cookie.Value != "" {
		_, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
		if err == nil {
			consentURL := &url.URL{Path: "/consent.html"}
			consentURL.RawQuery = q.Encode()
			http.Redirect(w, r, consentURL.String(), http.StatusFound)
			return
		}
	}

	loginURL := &url.URL{Path: "/authorize.html"}
	loginURL.RawQuery = q.Encode()
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
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
		http.Redirect(w, r, "/authorize.html?error=invalid_credentials&"+r.URL.RawQuery, http.StatusFound)
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

	consentURL := &url.URL{Path: "/consent.html"}

	params := url.Values{}
	for k, v := range r.Form {
		if k != "username" && k != "password" {
			params[k] = v
		}
	}
	consentURL.RawQuery = params.Encode()

	http.Redirect(w, r, consentURL.String(), http.StatusFound)
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

	code, err := h.authService.GenerateAuthorizationCodeForUser(r.Context(), user.ID, clientID, redirectURI,
		codeChallenge, codeChallengeMethod, scopes)
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
		http.Error(w, "invalid request form", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	w.Header().Set("Content-Type", "application/json")

	switch grantType {
	case "authorization_code":
		code := r.FormValue("code")
		clientID := r.FormValue("client_id")
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
		refreshToken := r.FormValue("refresh_token")
		if refreshToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "refresh_token is required"})
			return
		}

		tokens, err := h.authService.RefreshTokens(r.Context(), refreshToken)
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
