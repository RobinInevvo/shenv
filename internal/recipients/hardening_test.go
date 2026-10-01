package recipients

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRecipients replaces the recipients file with the given content.
func writeRecipients(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(Path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestInvisibleNamesAreRejected: graphic runes that render as nothing would
// let "alice<invisible>" pass for "alice" while being a different string with a
// different skeleton.
func TestInvisibleNamesAreRejected(t *testing.T) {
	for label, name := range map[string]string{
		"combining grapheme joiner":     "alice͏",
		"variation selector 1":          "alice︀",
		"variation selector 16":         "alice️",
		"supplementary variation sel.":  "alice\U000E0100",
		"Hangul filler":                 "ㅤalice",
		"halfwidth Hangul filler":       "aliceﾠ",
		"Hangul choseong filler":        "aliceᅟ",
		"Hangul jungseong filler":       "aliceᅠ",
		"braille blank":                 "alice⠀",
		"Khmer inherent vowel":          "alice឴",
		"Mongolian variation selector":  "alice᠋",
		"leading combining mark":        "́alice",
		"only combining marks":          "́̂",
		"zero-width joiner (Cf)":        "ali‍ce",
		"ideographic space (White_Sp.)": "alice　",
	} {
		if err := validateName(name); err == nil {
			t.Errorf("%s: validateName must reject %+q", label, name)
		}
	}
}

// TestLookalikeBypassesCollide: names that render like "alice" but survive
// validation must share its skeleton, so Load and Add treat them as the same
// person.
func TestLookalikeBypassesCollide(t *testing.T) {
	for label, name := range map[string]string{
		"math monospace":     "\U0001D68A\U0001D695\U0001D692\U0001D68C\U0001D68E",
		"math bold":          "\U0001D41A\U0001D425\U0001D422\U0001D41C\U0001D41E",
		"fullwidth":          "ａｌｉｃｅ",
		"uppercase":          "Alice",
		"all caps":           "ALICE",
		"Cyrillic а":         "аlice",
		"Cyrillic uppercase": "АLICE",
		"Greek uppercase":    "ΑLICE",
		"combining accent":   "alicé",
		"precomposed accent": "alicé",
	} {
		if err := validateName(name); err != nil {
			continue // rejected outright is just as good
		}
		if skeleton(name) != skeleton("alice") {
			t.Errorf("%s: %+q must collide with alice (skeleton %+q)", label, name, skeleton(name))
		}
	}
}

// TestInternationalNamesStillLoad: the stricter rules must not lock out an
// existing team whose members have ordinary non-ASCII names.
func TestInternationalNamesStillLoad(t *testing.T) {
	inRepo(t)
	names := []string{
		"alice", "bob-smith", "j.doe", "Jürgen", "Jürgen2", "José",
		"李雷", "Ольга", "Σωκράτης",
		"محمد", "हिन्दी", "さくら",
		"김민수", "Արամ",
	}
	var b strings.Builder
	for _, n := range names {
		if err := validateName(n); err != nil {
			t.Errorf("validateName(%q) = %v, want nil", n, err)
		}
		fmt.Fprintf(&b, "%s %s %s\n", n, testKey(t), testSignKey(t))
	}
	writeRecipients(t, b.String())
	members, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(members) != len(names) {
		t.Fatalf("loaded %d members, want %d", len(members), len(names))
	}
	if err := Add("Ольга2", testKey(t), testSignKey(t)); err != nil {
		t.Fatalf("Add of an ordinary Cyrillic name: %v", err)
	}
}

// TestCaseVariantIsImpersonation: "Alice" next to "alice" is the same name to
// a reader, so both doors refuse it with an error that says what to do.
func TestCaseVariantIsImpersonation(t *testing.T) {
	inRepo(t)
	if err := Add("alice", testKey(t), testSignKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := Add("Alice", testKey(t), testSignKey(t)); err == nil {
		t.Fatal("add-member must refuse a case variant of an existing member")
	}
	writeRecipients(t, fmt.Sprintf("alice %s %s\nAlice %s %s\n",
		testKey(t), testSignKey(t), testKey(t), testSignKey(t)))
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "look identical") || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("expected a lookalike error naming line 2, got %v", err)
	}
}

// TestLoadErrorsDoNotLeakContent: a committed recipients.shenv may be a symlink
// to (or simply contain) something secret; parse errors must point at the
// line, never echo it.
func TestLoadErrorsDoNotLeakContent(t *testing.T) {
	inRepo(t)
	const secret = "AWS_SECRET=hunter2-topsecret"
	key, signKey := testKey(t), testSignKey(t)
	for label, content := range map[string]string{
		"one field":           secret + "\n",
		"two fields":          "x " + secret + "\n",
		"four fields":         fmt.Sprintf("bob %s %s %s\n", key, signKey, secret),
		"secret as name":      fmt.Sprintf("%s\x1b %s %s\n", secret, key, signKey),
		"secret as age key":   fmt.Sprintf("bob %s %s\n", secret, signKey),
		"secret as sign key":  fmt.Sprintf("bob %s %s\n", key, secret),
		"leading-mark name":   fmt.Sprintf("́%s %s %s\n", secret, key, signKey),
		"invisible-char name": fmt.Sprintf("%sㅤ %s %s\n", secret, key, signKey),
	} {
		writeRecipients(t, "# header\n\n"+content)
		_, err := Load()
		if err == nil {
			t.Fatalf("%s: Load must fail", label)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks file content: %v", label, err)
		}
		if !strings.Contains(err.Error(), "line 3") {
			t.Errorf("%s: error must name the offending line, got %v", label, err)
		}
	}
}

// TestSaveRefusesSymlink: a committed symlink must not redirect the write to a
// file outside the repo, whether or not the target exists yet.
func TestSaveRefusesSymlink(t *testing.T) {
	members := []Member{{Name: "alice", Key: testKey(t), SignKey: testSignKey(t)}}

	t.Run("dangling", func(t *testing.T) {
		inRepo(t)
		target := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.Symlink(target, Path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := Save(members); err == nil {
			t.Fatal("Save must refuse a dangling symlink")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("Save created the symlink target: %v", err)
		}
		if err := Add("bob", testKey(t), testSignKey(t)); err == nil {
			t.Fatal("Add must refuse a dangling symlink")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("Add created the symlink target: %v", err)
		}
	})

	t.Run("existing", func(t *testing.T) {
		inRepo(t)
		target := filepath.Join(t.TempDir(), "victim")
		const original = "do not touch\n"
		if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, Path); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if err := Save(members); err == nil {
			t.Fatal("Save must refuse a symlink to an existing file")
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != original {
			t.Fatalf("target was modified: %q, %v", got, err)
		}
		if fi, err := os.Lstat(Path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("the symlink itself must be left in place: %v", err)
		}
	})
}

// TestSaveWritesRegularFile: the atomic write keeps the committed file's
// usual permissions.
func TestSaveWritesRegularFile(t *testing.T) {
	inRepo(t)
	if err := Add("alice", testKey(t), testSignKey(t)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(Path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("recipients file mode = %v, want regular 0644", fi.Mode())
	}
}
