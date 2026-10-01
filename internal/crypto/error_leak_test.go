package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const leakSecret = "hunter2"

func assertNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), leakSecret) {
		t.Fatalf("error leaks input content: %v", err)
	}
}

// TestDecryptErrorsDoNotEchoInput: env.shenv may be a committed symlink to a
// local file, and age's armor and header parsers quote the offending line.
// None of that may reach the error message.
func TestDecryptErrorsDoNotEchoInput(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"plain first line":   "password=" + leakSecret + "\n",
		"netrc":              "machine x login me password " + leakSecret + "\n",
		"bad header stanza":  armor.Header + "\n" + armorBody("age-encryption.org/v1\n-> "+leakSecret+"\x01\n") + "\n-----END AGE ENCRYPTED FILE-----\n",
		"bad closing line":   armor.Header + "\nYWdl\n" + leakSecret + "\n",
		"header then secret": armor.Header + "\n" + leakSecret + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecryptBytes([]byte(input), id)
			assertNoLeak(t, err)
			_, err = DecryptWithPassphrase([]byte(input), "pw")
			assertNoLeak(t, err)
		})
	}
}

// TestDecryptPlainFileIsNotBlob: a non-armored file gets the fixed message, not
// the membership hint, which would send the user hunting for the wrong problem.
func TestDecryptPlainFileIsNotBlob(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBytes([]byte("password="+leakSecret), id); !errors.Is(err, ErrNotBlob) {
		t.Fatalf("expected ErrNotBlob, got %v", err)
	}
}

// TestDecryptStrangerKeepsMemberHint: a genuine blob for other recipients still
// gets the "are you a member" hint.
func TestDecryptStrangerKeepsMemberHint(t *testing.T) {
	member, _ := age.GenerateX25519Identity()
	stranger, _ := age.GenerateX25519Identity()
	blob, err := EncryptBytes([]byte("A=1"), []age.Recipient{member.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptBytes(blob, stranger)
	if err == nil || !strings.Contains(err.Error(), "are you a member") {
		t.Fatalf("expected the membership hint, got %v", err)
	}
	if _, ok := errors.AsType[*age.NoIdentityMatchError](err); !ok {
		t.Fatalf("expected a wrapped NoIdentityMatchError, got %v", err)
	}
}

// TestDecryptLeadingWhitespaceStillWorks: the armor reader tolerates leading
// whitespace, so the pre-check must too.
func TestDecryptLeadingWhitespaceStillWorks(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	blob, err := EncryptBytes([]byte("A=1"), []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBytes(append([]byte("\n  \r\n"), blob...), id)
	if err != nil || string(got) != "A=1" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// TestDecryptWithPassphraseWrongKeepsHint: a wrong passphrase still says so.
func TestDecryptWithPassphraseWrongKeepsHint(t *testing.T) {
	blob, err := EncryptWithPassphrase([]byte("key"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptWithPassphrase(blob, "wrong"); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("expected a wrong-passphrase error, got %v", err)
	}
}

// armorBody base64-encodes s the way the armor writer would, without header or
// footer, so a test can smuggle bytes into a structurally valid armor body.
func armorBody(s string) string {
	var buf bytes.Buffer
	w := armor.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	return strings.Join(lines[1:len(lines)-1], "\n")
}
