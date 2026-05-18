package rest

import (
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

//go:embed locales/*.json
var localesFS embed.FS

var translations map[string]map[string]string

func LoadLocales() {
	translations = make(map[string]map[string]string)

	entries, err := localesFS.ReadDir("locales")
	if err != nil {
		slog.Error("Failed to read locales directory", "error", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		lang := strings.TrimSuffix(entry.Name(), ".json")
		data, err := localesFS.ReadFile("locales/" + entry.Name())
		if err != nil {
			slog.Error("Failed to read locale file", "file", entry.Name(), "error", err)
			continue
		}

		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			slog.Error("Failed to unmarshal locale file", "file", entry.Name(), "error", err)
			continue
		}

		translations[lang] = dict
		slog.Info("Loaded locale", "lang", lang)
	}
}

// GetLang determines the language from query param or Accept-Language header
func GetLang(r *http.Request) string {
	lang := r.URL.Query().Get("lang")
	if lang != "" {
		if _, ok := translations[lang]; ok {
			return lang
		}
	}

	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang != "" {
		parts := strings.Split(acceptLang, ",")
		if len(parts) > 0 {
			primaryLang := strings.Split(parts[0], "-")[0]
			if _, ok := translations[primaryLang]; ok {
				return primaryLang
			}
		}
	}

	return "en" // Default
}

// Translate returns the translation dictionary for the given request
func Translate(r *http.Request) map[string]string {
	lang := GetLang(r)
	if dict, ok := translations[lang]; ok {
		return dict
	}
	return translations["en"]
}
