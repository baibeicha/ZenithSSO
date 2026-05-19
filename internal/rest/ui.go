package rest

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

//go:embed web/templates/* web/static/*
var embedFS embed.FS

// GetFS returns a merged file system that prefers the local override folder (if it exists)
// or falls back to the embedded files.
func GetFS(customDir string) fs.FS {
	if customDir != "" {
		stat, err := os.Stat(customDir)
		if err == nil && stat.IsDir() {
			slog.Info("Using custom UI directory", "dir", customDir)
			return os.DirFS(customDir)
		}
		slog.Warn("Custom UI directory not found or not a directory, falling back to embedded", "dir", customDir)
	}

	// Try checking local ./web by default if no customDir provided
	if stat, err := os.Stat("web"); err == nil && stat.IsDir() {
		slog.Info("Using local ./web directory")
		return os.DirFS("web")
	}

	if stat, err := os.Stat("internal/rest/web"); err == nil && stat.IsDir() {
		slog.Info("Using local internal/rest/web directory")
		return os.DirFS("internal/rest/web")
	}

	slog.Info("Using embedded UI files")
	// return sub fs to match paths cleanly
	subFS, err := fs.Sub(embedFS, "web")
	if err != nil {
		panic(err)
	}
	return subFS
}

// ParseTemplates parses all html templates from the provided FS
func ParseTemplates(fileSystem fs.FS) *template.Template {
	tmpl := template.New("")
	err := fs.WalkDir(fileSystem, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".html" {
			b, err := fs.ReadFile(fileSystem, path)
			if err != nil {
				return err
			}
			_, err = tmpl.New(d.Name()).Parse(string(b))
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		slog.Error("error parsing templates", "err", err)
	}
	return tmpl
}
