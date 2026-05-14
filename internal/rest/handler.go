package rest

import (
	"encoding/json"
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
