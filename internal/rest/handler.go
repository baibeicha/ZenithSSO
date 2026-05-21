package rest

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"AuthServer/internal/encoder"
	"AuthServer/internal/usecase"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

type AuthHandler struct {
	authService    *usecase.AuthUsecase
	sessionService *usecase.SessionUsecase
	secured        bool
	issuer         string
	templates      *template.Template
}

func NewAuthHandler(as *usecase.AuthUsecase, sessionService *usecase.SessionUsecase, secured bool, issuer string, customDir string) *AuthHandler {
	uiFS := GetFS(customDir)
	tmpl := ParseTemplates(uiFS)

	LoadLocales()

	return &AuthHandler{
		authService:    as,
		sessionService: sessionService,
		secured:        secured,
		issuer:         issuer,
		templates:      tmpl,
	}
}

func (h *AuthHandler) RegisterRoutes(r chi.Router, customDir string) {
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

	r.Get("/login", h.LoginGETHandler)
	r.Post("/login", h.LoginPOSTHandler)
	r.Get("/settings", h.SettingsGETHandler)
	r.Post("/settings/revoke-session", h.RevokeSessionPOSTHandler)
	r.Post("/settings", h.SettingsPOSTHandler)
	r.Post("/logout", h.LogoutPOSTHandler)

	r.Get("/admin", h.AdminGETHandler)

	uiFS := GetFS(customDir)
	staticFS, err := fs.Sub(uiFS, "static")
	if err == nil {
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}
}

func (h *AuthHandler) RegisterGETHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"T": Translate(r),
	}
	err := h.templates.ExecuteTemplate(w, "register.html", data)
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

	claims := map[string]interface{}{
		"sub":      user.ID,
		"name":     user.Username,
		"email":    user.Email,
		"username": user.Username,
	}

	if user.FirstName != nil {
		claims["given_name"] = *user.FirstName
	}
	if user.LastName != nil {
		claims["family_name"] = *user.LastName
	}
	if user.AvatarURL != nil {
		claims["picture"] = *user.AvatarURL
	}
	if user.Locale != nil {
		claims["locale"] = *user.Locale
	}

	json.NewEncoder(w).Encode(claims)
}

func (h *AuthHandler) AuthorizeGETHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported_response_type: only 'code' is supported", http.StatusBadRequest)
		return
	}

	clientID := q.Get("client_id")

	_, err := h.authService.GetClientByID(r.Context(), clientID)
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
		"T":     Translate(r),
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

	data := map[string]interface{}{
		"T": Translate(r),
	}
	err = h.templates.ExecuteTemplate(w, "consent.html", data)
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
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	err := h.authService.Register(r.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
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

		client, err := h.authService.GetClientByID(r.Context(), clientID)
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

		ipAddress := r.RemoteAddr
		userAgent := r.UserAgent()

		tokens, err := h.authService.ExchangeAuthorizationCode(r.Context(), code, clientID, redirectURI, codeVerifier, ipAddress, userAgent)
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

		ipAddress := r.RemoteAddr
		userAgent := r.UserAgent()

		tokens, err := h.authService.RefreshTokens(r.Context(), refreshToken, clientID, ipAddress, userAgent)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(tokens)

	case "password", "":
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
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

		tokens, err := h.authService.Login(r.Context(), req.Username, req.Password)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(tokens)

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
func (h *AuthHandler) LoginGETHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sso_session")
	if err == nil && cookie.Value != "" {
		_, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
		if err == nil {
			http.Redirect(w, r, "/settings", http.StatusFound)
			return
		}
	}

	q := r.URL.Query()
	data := map[string]interface{}{
		"Error": q.Get("error"),
		"T":     Translate(r),
	}

	err = h.templates.ExecuteTemplate(w, "login.html", data)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (h *AuthHandler) LoginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.authService.ValidateUser(r.Context(), username, password)
	if err != nil {
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusFound)
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

	http.Redirect(w, r, "/settings", http.StatusFound)
}

func (h *AuthHandler) SettingsGETHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sso_session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	user, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	isAdmin := false
	for _, scope := range user.Scopes {
		if scope.Name == "root" {
			isAdmin = true
			break
		}
	}

	sessions, _ := h.sessionService.GetUserSessions(r.Context(), user.ID)

	q := r.URL.Query()
	data := map[string]interface{}{
		"User":           user,
		"Error":          q.Get("error"),
		"Success":        q.Get("success"),
		"IsAdmin":        isAdmin,
		"Sessions":       sessions,
		"CurrentSession": cookie.Value,
		"T":              Translate(r),
	}

	err = h.templates.ExecuteTemplate(w, "settings.html", data)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (h *AuthHandler) RevokeSessionPOSTHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sso_session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	user, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?error=invalid_request", http.StatusFound)
		return
	}

	tokenToRevoke := r.FormValue("token")
	allExceptCurrent := r.FormValue("all_except_current")

	if allExceptCurrent == "true" {
		err = h.sessionService.RevokeAllExceptCurrent(r.Context(), user.ID, cookie.Value)
	} else {
		err = h.sessionService.RevokeSession(r.Context(), user.ID, tokenToRevoke)
	}

	if err != nil {
		http.Redirect(w, r, "/settings?error=revoke_failed", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings?success=Session revoked", http.StatusFound)
}

func (h *AuthHandler) SettingsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sso_session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	user, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?error=invalid_request", http.StatusFound)
		return
	}

	firstName := r.FormValue("first_name")
	lastName := r.FormValue("last_name")
	avatarURL := r.FormValue("avatar_url")
	locale := r.FormValue("locale")

	if firstName != "" {
		user.FirstName = &firstName
	} else {
		user.FirstName = nil
	}
	if lastName != "" {
		user.LastName = &lastName
	} else {
		user.LastName = nil
	}
	if avatarURL != "" {
		user.AvatarURL = &avatarURL
	} else {
		user.AvatarURL = nil
	}
	if locale != "" {
		user.Locale = &locale
	} else {
		user.Locale = nil
	}

	err = h.authService.UpdateUserProfile(r.Context(), user)
	if err != nil {
		http.Redirect(w, r, "/settings?error=update_failed", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings?success=Профиль%20успешно%20обновлен", http.StatusFound)
}

func (h *AuthHandler) LogoutPOSTHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "sso_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secured,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}
func (h *AuthHandler) AdminGETHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("sso_session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	user, err := h.authService.GetUserInfo(r.Context(), cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	isAdmin := false
	for _, scope := range user.Scopes {
		if scope.Name == "root" {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		http.Error(w, "forbidden: admin access required", http.StatusForbidden)
		return
	}

	users, err := h.authService.GetAllUsers(r.Context())

	q := r.URL.Query()
	data := map[string]interface{}{
		"User":  user,
		"Users": users,
		"Error": q.Get("error"),
		"T":     Translate(r),
	}

	if err != nil {
		data["Error"] = "Failed to load users"
	}

	err = h.templates.ExecuteTemplate(w, "admin.html", data)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
