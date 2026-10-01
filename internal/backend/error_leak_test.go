package backend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const leakSecret = "hunter2"

// assertNoLeak fails if err's message contains the secret.
func assertNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), leakSecret) {
		t.Fatalf("error leaks file content: %v", err)
	}
}

// TestConfigErrorsDoNotEchoContent: a committed config.shenv may be a symlink
// to /proc/self/environ or ~/.netrc. Parse errors must point at the line
// without printing it, or local secrets land in the terminal or a CI log.
func TestConfigErrorsDoNotEchoContent(t *testing.T) {
	for name, content := range map[string]string{
		"environ-style NUL": "SECRET_TOKEN=" + leakSecret + "\x00HOME=/root\x00",
		"netrc-style":       "machine example.com login me password " + leakSecret + "\n",
		"escape in value":   "get = echo " + leakSecret + "\x1b[2K\n",
		"control in key":    "SEC\x01" + leakSecret + " = x\n",
	} {
		t.Run(name, func(t *testing.T) {
			inRepo(t)
			writeConfig(t, content)
			_, err := Load()
			assertNoLeak(t, err)
			if !strings.Contains(err.Error(), "line 1") {
				t.Fatalf("error should still name the line: %v", err)
			}
		})
	}
}

// TestConfigErrorNamesIdentifierKey: a plain identifier key is safe to show and
// helps the user find the offending line.
func TestConfigErrorNamesIdentifierKey(t *testing.T) {
	inRepo(t)
	writeConfig(t, "backend = file\nget = cat x\x1b[2K\n")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "line 2 (key get)") {
		t.Fatalf("expected the error to name key `get` on line 2, got %v", err)
	}
}

// TestConfigSymlinkErrorDoesNotEchoTarget follows a real symlink, the shape of
// the attack: the link is committed, the target is a local secrets file.
func TestConfigSymlinkErrorDoesNotEchoTarget(t *testing.T) {
	inRepo(t)
	target := filepath.Join(t.TempDir(), "netrc")
	if err := os.WriteFile(target, []byte("password "+leakSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := Load()
	assertNoLeak(t, err)
}

// TestFileBackendGetErrorDoesNotEchoContent: Get keeps following a symlinked
// blob (some setups link it on purpose), so its own errors must carry no file
// content either.
func TestFileBackendGetErrorDoesNotEchoContent(t *testing.T) {
	inRepo(t)
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte(strings.Repeat(leakSecret, MaxBlobSize/len(leakSecret)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, DefaultBlobPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := FileBackend{Path: DefaultBlobPath}.Get()
	assertNoLeak(t, err)
}
