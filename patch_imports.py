import re

with open("internal/rest/handler.go", "r") as f:
    data = f.read()

imports = """import (
	"bytes"
	"log/slog"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"AuthServer/internal/encoder"
	"AuthServer/internal/usecase"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)"""

data = re.sub(r'import \(\n([^\)]+)\n\)', imports, data)

with open("internal/rest/handler.go", "w") as f:
    f.write(data)
