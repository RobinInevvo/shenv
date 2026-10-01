package command

import (
	"os"
	"strings"
	"testing"
)

// trackCaseVariant puts a file whose name differs from the destination only in
// case into the index — never into a commit — the way a repository that once
// committed `.ENV` looks to git.
func trackCaseVariant(t *testing.T, name string, ignoreCase bool) {
	t.Helper()
	gitInit(t)
	value := "false"
	if ignoreCase {
		value = "true"
	}
	git(t, "config", "core.ignorecase", value)
	if err := os.WriteFile(name, []byte("tracked content"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, "add", "-f", "--", name)
}

func mustGitTarget(t *testing.T, path string) *gitTarget {
	t.Helper()
	target, err := resolveGitTarget(path)
	if err != nil || target == nil {
		t.Fatalf("resolveGitTarget(%s) = %v, %v", path, target, err)
	}
	return target
}

// TestOpenRefusesCaseVariantTrackedEnv: with core.ignorecase a tracked `.ENV`
// is the same file as `.env`, so the exact-spelling pathspec git answers "not
// tracked" for must not let open write plaintext over it.
func TestOpenRefusesCaseVariantTrackedEnv(t *testing.T) {
	requireGit(t)
	setup(t)
	mustInit(t)
	sealMarker(t)
	trackCaseVariant(t, ".ENV", true)

	err := Open([]string{"--force"})
	if err == nil || !strings.Contains(err.Error(), "tracked by git as .ENV") {
		t.Fatalf("open over a case-variant tracked file must be refused, got %v", err)
	}
	if got, _ := os.ReadFile(".ENV"); string(got) != "tracked content" {
		t.Fatalf("tracked file must be untouched, got %q", got)
	}
}

// TestRefuseTrackedCaseVariantInDirectory: the parent directory's case can
// differ too, so the comparison covers the whole relative path.
func TestRefuseTrackedCaseVariantInDirectory(t *testing.T) {
	requireGit(t)
	setup(t)
	if err := os.Mkdir("Sub", 0o755); err != nil {
		t.Fatal(err)
	}
	trackCaseVariant(t, "Sub/.Env", true)
	// A no-op on a case-insensitive filesystem; elsewhere the parent has to
	// exist for the destination to be resolved.
	if err := os.MkdirAll("sub", 0o755); err != nil {
		t.Fatal(err)
	}

	err := mustGitTarget(t, "sub/.env").refuseTracked()
	if err == nil || !strings.Contains(err.Error(), "tracked by git as Sub/.Env") {
		t.Fatalf("sub/.env must count as tracked via Sub/.Env, got %v", err)
	}
}

// TestRefuseTrackedCaseSensitiveRepo: without core.ignorecase git keeps `.ENV`
// and `.env` apart, and so does the guard.
func TestRefuseTrackedCaseSensitiveRepo(t *testing.T) {
	requireGit(t)
	setup(t)
	trackCaseVariant(t, ".ENV", false)

	if err := mustGitTarget(t, defaultEnvFile).refuseTracked(); err != nil {
		t.Fatalf("a case-sensitive repository must not treat .ENV as .env: %v", err)
	}
	err := mustGitTarget(t, ".ENV").refuseTracked()
	if err == nil || !strings.Contains(err.Error(), ".ENV is tracked by git,") {
		t.Fatalf("the exact tracked name must still be refused, got %v", err)
	}
}

// TestIsGitTrackedCaseVariant: status must warn about a case-variant tracked
// .env exactly when git treats the worktree as case-insensitive.
func TestIsGitTrackedCaseVariant(t *testing.T) {
	requireGit(t)
	for _, ignoreCase := range []bool{true, false} {
		setup(t)
		trackCaseVariant(t, ".ENV", ignoreCase)
		if got := isGitTracked(defaultEnvFile); got != ignoreCase {
			t.Errorf("core.ignorecase=%v: isGitTracked(.env) = %v", ignoreCase, got)
		}
		if !isGitTracked(".ENV") {
			t.Errorf("core.ignorecase=%v: the exact tracked name must count as tracked", ignoreCase)
		}
	}
}
