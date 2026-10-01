package backend

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// readConfig parses a simple `key = value` config file. Blank lines and lines
// starting with '#' are ignored. A missing file yields an empty config (which
// Load treats as the default file backend). Values keep everything after the
// first '=', so exec commands may contain '=' freely.
func readConfig(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	cfg := map[string]string{}
	lineNo := 0
	for raw := range strings.SplitSeq(string(data), "\n") {
		lineNo++
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// The config ships with the clone, and exec commands from it are shown in
		// the trust prompt before running. An embedded terminal escape (ESC is not
		// whitespace, so TrimSpace keeps it) could redraw that prompt to hide what
		// is being approved, and bidi or zero-width format runes could reorder or
		// hide part of the command the same way. No key or single-line command
		// needs either.
		if i := strings.IndexFunc(line, func(r rune) bool { return r != '\t' && !unicode.IsGraphic(r) }); i >= 0 {
			return nil, fmt.Errorf("%s line %d%s: control character or invisible rune", path, lineNo, keyHint(line))
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s line %d: missing '='", path, lineNo)
		}
		cfg[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return cfg, nil
}

// keyHint names the key of a rejected line so the user can find it, but only
// when the key is a plain identifier. Parse errors never quote the line itself:
// a committed config.shenv may be a symlink to /proc/self/environ or ~/.netrc,
// and echoing its content would print local secrets into a terminal or CI log.
func keyHint(line string) string {
	key, _, ok := strings.Cut(line, "=")
	key = strings.TrimSpace(key)
	if !ok || key == "" || len(key) > 64 {
		return ""
	}
	for _, r := range key {
		if r != '_' && r != '-' && r != '.' && (r > unicode.MaxASCII || !unicode.IsLetter(r) && !unicode.IsDigit(r)) {
			return ""
		}
	}
	return fmt.Sprintf(" (key %s)", key)
}
