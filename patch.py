with open("internal/rest/i18n.go", "r") as f:
    data = f.read()

s = """// Translate returns the translation dictionary for the given request
func Translate(r *http.Request) map[string]string {
	lang := GetLang(r)
	if dict, ok := translations[lang]; ok {
		return dict
	}
	return translations["en"]
}"""

r = """// Translate returns a translation function for the given request
func Translate(r *http.Request) func(string) string {
	lang := GetLang(r)
	dict, ok := translations[lang]
	if !ok {
		dict = translations["en"]
	}

	return func(key string) string {
		if val, exists := dict[key]; exists {
			return val
		}
		return key
	}
}"""

data = data.replace(s, r)

with open("internal/rest/i18n.go", "w") as f:
    f.write(data)
