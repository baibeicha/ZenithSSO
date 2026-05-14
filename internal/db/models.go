package db

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type User struct {
	ID       uint64     `db:"id"`
	Username string     `db:"username"`
	Email    string     `db:"email"`
	Password string     `db:"password"`
	Scopes   ScopesList `db:"scopes"`
}

type Scope struct {
	ID          uint64 `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	WorkspaceID uint64 `db:"workspace_id" json:"workspace_id"`
}

type Workspace struct {
	ID     uint64     `db:"id"`
	Name   string     `db:"name"`
	Scopes ScopesList `db:"scopes"`
}

type ScopesList []Scope

func (s *ScopesList) Scan(val any) error {
	if val == nil {
		*s = make(ScopesList, 0)
		return nil
	}
	b, ok := val.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	return json.Unmarshal(b, s)
}

func (s *ScopesList) String() string {
	builder := strings.Builder{}
	for _, scope := range *s {
		builder.WriteString(strconv.FormatUint(scope.WorkspaceID, 10))
		builder.WriteString("_")
		builder.WriteString(scope.Name)
		builder.WriteString(";")
	}

	if builder.Len() > 0 {
		return builder.String()[:builder.Len()-1]
	}

	return ""
}

func (s *ScopesList) StringFromAllowed(allowedScopes string) string {
	builder := strings.Builder{}
	for _, scope := range *s {
		if strings.Contains(allowedScopes, scope.Name) {
			builder.WriteString(strconv.FormatUint(scope.WorkspaceID, 10))
			builder.WriteString("_")
			builder.WriteString(scope.Name)
			builder.WriteString(";")
		}
	}

	if builder.Len() > 0 {
		return builder.String()[:builder.Len()-1]
	}

	return ""
}

type Token struct {
	Id        uint64    `db:"id"`
	Token     string    `db:"token"`
	ExpiresAt time.Time `db:"expires_at"`
	UserId    uint64    `db:"user_id"`
}

type Client struct {
	ID               string          `db:"id"`
	ClientID         string          `db:"client_id"`
	ClientSecretHash string          `db:"client_secret_hash"`
	RedirectURIs     json.RawMessage `db:"redirect_uris"`
	AllowedScopes    json.RawMessage `db:"allowed_scopes"`
}

type AuthCode struct {
	Code                string    `db:"code"`
	ClientID            string    `db:"client_id"`
	UserID              uint64    `db:"user_id"`
	RedirectURI         string    `db:"redirect_uri"`
	CodeChallenge       string    `db:"code_challenge"`
	CodeChallengeMethod string    `db:"code_challenge_method"`
	Scopes              string    `db:"scopes"`
	ExpiresAt           time.Time `db:"expires_at"`
}
