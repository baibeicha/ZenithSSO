import glob
import re

for filepath in glob.glob("internal/rest/web/templates/*.html"):
    with open(filepath, "r") as f:
        data = f.read()

    data = re.sub(r'\{\{index \.T "([^"]+)"\}\}', r'{{.T "\1"}}', data)

    with open(filepath, "w") as f:
        f.write(data)
