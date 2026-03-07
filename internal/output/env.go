package output

import (
	"sort"
	"strings"
)

// FormatEnv renders key/value data in .env format.
func FormatEnv(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteString("=")
		b.WriteString(quoteEnvValue(values[key]))
		b.WriteString("\n")
	}
	return b.String()
}

func quoteEnvValue(raw string) string {
	if raw == "" {
		return `""`
	}

	needsQuote := false
	for _, ch := range raw {
		if ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '"' || ch == '\\' || ch == '#' || ch == '=' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return raw
	}

	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
		"\t", `\t`,
	)
	return `"` + replacer.Replace(raw) + `"`
}
