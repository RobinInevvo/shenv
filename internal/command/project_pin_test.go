package command

import (
	"os"
	"sort"
	"strings"
	"testing"

	"shenv/internal/recipients"
)

// These tests cover pinning the project id alongside the member list: whoever
// can commit to the repo can rewrite config.shenv, and a swapped id lets a blob
// a shared member sealed for another repo verify here.

// pinnedProject returns the project line of the pin, failing if there is none.
func pinnedProject(t *testing.T) string {
	t.Helper()
	p, hasProject, err := readPin()
	if err != nil || p == nil || !hasProject {
		t.Fatalf("expected a pin with a project line (pin=%v hasProject=%v err=%v)", p, hasProject, err)
	}
	return p.project
}

// writeLegacyPin rewrites the pin the way shenv wrote it before the project id
// was pinned: member entries only.
func writeLegacyPin(t *testing.T) {
	t.Helper()
	members, err := recipients.Load()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for k := range recipientSet(members) {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	path, err := pushedRecipientsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// pinProject rewrites only the pinned project id, as if config.shenv had named
// that id when this machine last trusted it.
func pinProject(t *testing.T, id string) {
	t.Helper()
	members, err := recipients.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := writePin(recipientSet(members), id); err != nil {
		t.Fatal(err)
	}
}

func readEnvFile(t *testing.T) string {
	t.Helper()
	got, err := os.ReadFile(defaultEnvFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func TestOpenAsksBeforeTrustingChangedProject(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=a\n")
	setProject(t, "project-b")

	err := openErr(t)
	if err == nil || !strings.Contains(err.Error(), "project id") {
		t.Fatalf("an unconfirmed project change must block open, got %v", err)
	}
	os.Remove(defaultEnvFile)
	feed(t, "n\n")
	if err := Open(nil); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("a declined project change must block open, got %v", err)
	}
	if got := pinnedProject(t); got != "project-a" {
		t.Fatalf("a declined change must keep the pin, got %q", got)
	}

	// Confirming the change still doesn't make another project's blob verify:
	// the pin only decides which id is trusted, the signature does the rest.
	os.Remove(defaultEnvFile)
	feed(t, "y\n")
	err = Open(nil)
	if err == nil || strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("want a verification error after confirming, got %v", err)
	}
	if got := pinnedProject(t); got != "project-b" {
		t.Fatalf("a confirmed change must update the pin, got %q", got)
	}
}

func TestOpenAcceptsConfirmedProjectChange(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=a\n")
	pinProject(t, "project-old")

	os.Remove(defaultEnvFile)
	feed(t, "y\n")
	if err := Open(nil); err != nil {
		t.Fatalf("open after confirming: %v", err)
	}
	if got := readEnvFile(t); got != "TOKEN=a\n" {
		t.Fatalf("opened %q", got)
	}
	if err := openErr(t); err != nil {
		t.Fatalf("open must not ask twice: %v", err)
	}
}

func TestProjectChangeEnvOverride(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=a\n")
	pinProject(t, "project-old")

	t.Setenv("SHENV_TRUST_RECIPIENTS", "1")
	if err := openErr(t); err != nil {
		t.Fatalf("override must accept the change: %v", err)
	}
	if got := pinnedProject(t); got != "project-a" {
		t.Fatalf("an accepted change must update the pin, got %q", got)
	}
}

// TestOpenAsksWhenProjectRemoved: dropping the line is how an old unbound blob
// would be planted.
func TestOpenAsksWhenProjectRemoved(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=a\n")
	setProject(t, "")

	err := openErr(t)
	if err == nil || !strings.Contains(err.Error(), "project id") {
		t.Fatalf("removing the project line must need confirmation, got %v", err)
	}
	if got := pinnedProject(t); got != "project-a" {
		t.Fatalf("an unconfirmed removal must keep the pin, got %q", got)
	}
}

func TestSealAsksBeforeChangedProject(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=a\n")
	setProject(t, "project-b")

	// The first answer is for the lockout guard: the old blob is bound to
	// project-a, so it can't be verified under project-b.
	writeEnv(t, "TOKEN=b\n")
	feed(t, "y\nn\n")
	if err := Seal(nil); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if got := pinnedProject(t); got != "project-a" {
		t.Fatalf("a declined seal must keep the pin, got %q", got)
	}
	setProject(t, "project-a")
	if err := openErr(t); err != nil {
		t.Fatalf("the declined seal must leave the old blob: %v", err)
	}
	if got := readEnvFile(t); got != "TOKEN=a\n" {
		t.Fatalf("a declined seal replaced the blob: %q", got)
	}

	setProject(t, "project-b")
	writeEnv(t, "TOKEN=b\n")
	feed(t, "y\ny\n")
	if err := Seal(nil); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := openErr(t); err != nil {
		t.Fatalf("open after a confirmed seal: %v", err)
	}
	if got := readEnvFile(t); got != "TOKEN=b\n" {
		t.Fatalf("opened %q after a confirmed seal", got)
	}
}

// TestLegacyPinAdoptsProject: pins from before the project id was pinned must
// upgrade without a prompt, or every CI run breaks on the shenv update.
func TestLegacyPinAdoptsProject(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=a\n")
	writeLegacyPin(t)

	if err := openErr(t); err != nil {
		t.Fatalf("a legacy pin must not prompt: %v", err)
	}
	if got := pinnedProject(t); got != "project-a" {
		t.Fatalf("a legacy pin must adopt the current project, got %q", got)
	}

	setProject(t, "project-b")
	if err := openErr(t); err == nil || !strings.Contains(err.Error(), "project id") {
		t.Fatalf("after the upgrade a project change must be caught, got %v", err)
	}
}

func TestLegacyPinWithoutProjectLine(t *testing.T) {
	setup(t)
	mustInit(t)
	sealEnvFile(t, "TOKEN=x\n")
	writeLegacyPin(t)

	if err := openErr(t); err != nil {
		t.Fatalf("a repo without a project line must keep working: %v", err)
	}
	if got := pinnedProject(t); got != "" {
		t.Fatalf("want an empty pinned project, got %q", got)
	}
	if err := openErr(t); err != nil {
		t.Fatalf("unchanged config must not prompt: %v", err)
	}
}

func TestSealUpgradesLegacyPinWithoutPrompt(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=a\n")
	writeLegacyPin(t)

	writeEnv(t, "TOKEN=b\n")
	feed(t, "") // must not read any input
	if err := Seal(nil); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := openErr(t); err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readEnvFile(t); got != "TOKEN=b\n" {
		t.Fatalf("a legacy pin must not stop the seal, opened %q", got)
	}
}

func TestPinRoundTripsProject(t *testing.T) {
	setup(t)
	if err := writePin(recipientSet(members("me", "age1self")), "project-a"); err != nil {
		t.Fatal(err)
	}
	p, hasProject, err := readPin()
	if err != nil || p == nil || !hasProject {
		t.Fatalf("pin=%v hasProject=%v err=%v", p, hasProject, err)
	}
	if p.project != "project-a" || len(p.members) != 1 || !p.members["me\tage1self\t"] {
		t.Fatalf("round-trip mismatch: %+v", p)
	}
}
