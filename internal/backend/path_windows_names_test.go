package backend

import "testing"

// TestBlobPathRejectsWindowsAliases: Win32 strips trailing dots and spaces from
// path components and resolves 8.3 short names, so these paths open .gitignore,
// .git/config or shenv's own files on a Windows teammate's machine even though
// they compare unequal to the reserved names. The config is shared across
// operating systems, so they must be refused on every platform.
func TestBlobPathRejectsWindowsAliases(t *testing.T) {
	for _, path := range []string{
		".gitignore.", ".gitignore..", ".gitignore ", ".gitignore. .",
		".git./config", ".git /config", ".git.\\config",
		"env.shenv ", "recipients.shenv ", "config.shenv.", "sub/.env.",
		"GITIGN~1", "sub/RECIPI~1.SHE", "GIT~1/config",
		".gitignore::$DATA", "sub/.env:stream",
		"sub\\.env", "sub\\.gitignore", "..\\outside.age",
	} {
		if err := validateBlobPath(path); err == nil {
			t.Errorf("blob path %q must be rejected", path)
		}
	}
}

// TestBlobPathAllowsOrdinaryNames: the Windows-alias rules must not catch the
// names real setups use.
func TestBlobPathAllowsOrdinaryNames(t *testing.T) {
	for _, path := range []string{
		"env.shenv", "secrets/env.shenv", ".env.enc", "./env.shenv",
		"blobs/team.v2.shenv", "a/b/c/env.shenv", "my~blob.shenv", "env~.shenv",
	} {
		if err := validateBlobPath(path); err != nil {
			t.Errorf("blob path %q should be allowed: %v", path, err)
		}
	}
}

// TestLoadRejectsTrailingDotPath exercises the check through config.shenv.
func TestLoadRejectsTrailingDotPath(t *testing.T) {
	inRepo(t)
	writeConfig(t, "backend = file\npath = .git./config\n")
	if _, err := Load(); err == nil {
		t.Fatal("path .git./config must be rejected")
	}
}
