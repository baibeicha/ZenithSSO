import glob
import re

for filepath in glob.glob("internal/rest/web/templates/*.html"):
    with open(filepath, "r") as f:
        data = f.read()

    # The templates might have variables like `.User` or `.Error`.
    # Because we are wrapping them in `TemplateData{Data: map, dict: map}`,
    # those map variables are now inside `.Data`.
    # Wait, the user wants `{{.T "key"}}`.
    # If the struct is:
    # type TemplateData struct {
    #     User domain.User
    #     Error string
    #     // ...
    # }
    # Then `{{.User}}` still works.
    # But since it's dynamic (Data map[string]interface{}), `{{.Data.User}}` would be needed.

    # Wait, instead of a dynamic map, I can use the template FuncMap globally or `call .T` is much easier.
    # Actually, using `call` is perfectly valid Go template syntax: `{{call .T "key"}}`
    # Let's see if the user specifically required EXACTLY `{{ .T "key" }}`.
    # The user said: "templates correctly use function syntax: {{ .T "key" }}" and "T is not a method but has arguments".
    # Wait, if `.T` is passed via `FuncMap` instead of `data["T"]`, it is a function that can be called directly as `{{ T "key" }}` (without the dot!).

    pass
