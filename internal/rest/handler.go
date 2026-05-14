package rest

import (
	"encoding/json"
	"fmt"
	"net/http"

	"AuthServer/api"
	"AuthServer/internal"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

type AuthHandler struct {
	authService *internal.AuthServer
}

func NewAuthHandler(as *internal.AuthServer) *AuthHandler {
	return &AuthHandler{authService: as}
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

	r.Post("/api/v1/register", h.RegisterHandler)
	r.Post("/api/v1/token", h.TokenHandler)
	r.Post("/api/v1/authorize", h.AuthorizeHandler)
}

func (h *AuthHandler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	code, err := h.authService.GenerateAuthorizationCode(r.Context(), username, password,
		clientID, redirectURI, codeChallenge, codeChallengeMethod)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
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
	var req api.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
