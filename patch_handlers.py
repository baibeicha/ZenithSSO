import re

with open("internal/rest/handler.go", "r") as f:
    data = f.read()

def replace_execute_template(match):
    template_name = match.group(2)
    prefix = match.group(1)
    is_colon = ":=" in match.group(0).split('\n')[0]

    decl = "err :=" if is_colon else "err ="

    return f"""var buf bytes.Buffer
{prefix}{decl} h.templates.ExecuteTemplate(&buf, "{template_name}", data)
{prefix}if err != nil {{
{prefix}	slog.Error("template execution error", "err", err)
{prefix}	http.Error(w, "internal server error", http.StatusInternalServerError)
{prefix}	return
{prefix}}}
{prefix}buf.WriteTo(w)"""

data = re.sub(r'([ \t]*)err [:]?= h\.templates\.ExecuteTemplate\(w, "([^"]+)", data\)\n[ \t]*if err != nil {\n[ \t]*http\.Error\(w, "internal server error", http\.StatusInternalServerError\)\n[ \t]*}', replace_execute_template, data)

if '"bytes"' not in data:
    data = data.replace('"context"', '"bytes"\n\t"context"')

if '"log/slog"' not in data:
    data = data.replace('"bytes"\n\t"context"', '"bytes"\n\t"context"\n\t"log/slog"')

# Also fix the Session Tracking again
data = re.sub(
    r'sessionToken, err := h\.authService\.CreateSessionToken\(user\)',
    r"""ipAddress := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ipAddress = forwarded
	}
	userAgent := r.UserAgent()

	sessionToken, err := h.authService.CreateSessionToken(user, ipAddress, userAgent)""",
    data
)

data = data.replace('	tDict := Translate(r)\n	tFunc := func(key string) string {\n		if val, exists := tDict[key]; exists {\n			return val\n		}\n		return key\n	}\n	data := map[string]interface{}{', '	tDict := Translate(r)\n	tFunc := func(key string) string {\n		if val, exists := tDict[key]; exists {\n			return val\n		}\n		return key\n	}\n	data := map[string]interface{}{')

with open("internal/rest/handler.go", "w") as f:
    f.write(data)
