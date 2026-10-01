// Package recipients manages the per-repo list of team members allowed to decrypt.
// The file holds only public keys, so it is safe to commit.
package recipients

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"shenv/internal/backend"
	"shenv/internal/crypto"
)

// Path is the per-repo recipients file, relative to the repo root.
const Path = "recipients.shenv"

// Member is one entry: a friendly name, an age public key for encryption, and
// an Ed25519 verify key so pulls can check who signed the blob.
type Member struct {
	Name    string
	Key     string // age1... public key
	SignKey string // base64 Ed25519 verify key
}

// Load reads the team list. A missing file is treated as empty.
//
// The file arrives over an untrusted channel (a clone, a merge), so nothing in
// it is echoed back before it has been validated: a committed symlink pointing
// at a local secret would otherwise have that secret printed in a parse error.
// Errors name the line number and the offending field instead.
func Load() ([]Member, error) {
	data, err := os.ReadFile(Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var members []Member
	seen := map[string]bool{}
	seenLook := map[string]string{} // skeleton → member name
	seenKey := map[string]string{}  // age key → member name
	seenSign := map[string]string{} // sign key → member name
	lineNo := 0
	for line := range strings.SplitSeq(string(data), "\n") {
		lineNo++
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s line %d: expected 3 fields `name age1... signing-key`, found %d (`shenv whoami` prints both keys)", Path, lineNo, len(fields))
		}
		// The name rules enforced on `add-member` must hold on load too: a control
		// character in a name could smuggle terminal escapes into prompts.
		if err := validateName(fields[0]); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", Path, lineNo, err)
		}
		// Validate both key fields here, not just where they happen to be parsed
		// later: push's recipient prompt echoes entries from this file, and a
		// "key" carrying terminal escapes could redraw the very prompt meant to
		// expose a planted recipient. Valid bech32/base64 is control-char-free.
		// The parsers' errors quote the rejected input, so they are not wrapped.
		if _, err := age.ParseX25519Recipient(fields[1]); err != nil {
			return nil, fmt.Errorf("%s line %d: member %q has an invalid public key (expected an age1... key)", Path, lineNo, fields[0])
		}
		if _, err := crypto.ParseVerifyKey(fields[2]); err != nil {
			return nil, fmt.Errorf("%s line %d: member %q has an invalid signing key (expected the base64 key from `shenv whoami`)", Path, lineNo, fields[0])
		}
		// Signer lookup during pull is by name and takes the first match — a
		// duplicate would let a shadow entry hijack an existing member's identity.
		if seen[fields[0]] {
			return nil, fmt.Errorf("%s line %d: duplicate member %q — names must be unique so signatures can't be verified against the wrong key", Path, lineNo, fields[0])
		}
		seen[fields[0]] = true
		// Exact-string uniqueness is not enough for a name people read: "аlice"
		// with a Cyrillic а, or "Alice", is a different string and the same word
		// on screen, so "signed by аlice" would pass for the real member.
		if other, dup := seenLook[skeleton(fields[0])]; dup {
			return nil, fmt.Errorf("%s line %d: members %q and %q look identical — they differ only in case, accents, invisible marks, or lookalike letters from another script; remove or rename one of them", Path, lineNo, other, fields[0])
		}
		seenLook[skeleton(fields[0])] = fields[0]
		// Keys must be one-to-one with names as well: signature attribution maps
		// name → sign key, and push identifies "you" by age key. An entry reusing
		// another member's keys would make "signed by <name>" ambiguous.
		if other, dup := seenKey[fields[1]]; dup {
			return nil, fmt.Errorf("members %q and %q in %s share the same public key — each member needs their own key so pushes attribute to the right person", other, fields[0], Path)
		}
		if other, dup := seenSign[fields[2]]; dup {
			return nil, fmt.Errorf("members %q and %q in %s share the same signing key — each member needs their own key so signatures attribute to the right person", other, fields[0], Path)
		}
		seenKey[fields[1]], seenSign[fields[2]] = fields[0], fields[0]
		members = append(members, Member{Name: fields[0], Key: fields[1], SignKey: fields[2]})
	}
	return members, nil
}

// Save writes the team list back, sorted by name for stable diffs. A symlink at
// Path is refused rather than followed, so a committed link can't redirect the
// write outside the repo; the atomic rename means a crash never leaves a
// truncated member list.
func Save(members []Member) error {
	if err := backend.RejectSymlinks(Path); err != nil {
		return err
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })

	var b strings.Builder
	b.WriteString("# shenv recipients — per member: name, age public key (encryption),\n")
	b.WriteString("# Ed25519 verify key (signing). Safe to commit. Managed by `shenv add-member` / `shenv init`.\n")
	for _, m := range members {
		fmt.Fprintf(&b, "%s %s %s\n", m.Name, m.Key, m.SignKey)
	}

	return backend.WriteFileAtomic(Path, []byte(b.String()), 0o644)
}

// Add inserts or updates a member and persists the list. Matching an existing
// entry by name refreshes its keys; matching by key renames it (e.g. `shenv
// init new-name` when already registered) — one person stays one entry, since
// Load rejects duplicate keys to keep signature attribution unambiguous.
func Add(name, key, signKey string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if _, err := age.ParseX25519Recipient(key); err != nil {
		return fmt.Errorf("invalid public key %q: %w", key, err)
	}
	if _, err := crypto.ParseVerifyKey(signKey); err != nil {
		return err
	}
	members, err := Load()
	if err != nil {
		return err
	}

	byName, byKey := -1, -1
	for i, m := range members {
		if m.Name == name {
			byName = i
		}
		if m.Key == key {
			byKey = i
		}
	}
	switch {
	case byKey >= 0 && byName >= 0 && byKey != byName:
		return fmt.Errorf("key already belongs to %q — `shenv remove-member` one of %q/%q first", members[byKey].Name, members[byKey].Name, name)
	case byKey >= 0:
		members[byKey] = Member{Name: name, Key: key, SignKey: signKey}
	case byName >= 0:
		members[byName].Key, members[byName].SignKey = key, signKey
	default:
		members = append(members, Member{Name: name, Key: key, SignKey: signKey})
	}

	// Never persist a list the next Load would reject (a sign key colliding with
	// a different member's would brick the file until hand-edited).
	for _, m := range members {
		if m.Name != name && skeleton(m.Name) == skeleton(name) {
			return fmt.Errorf("name %q looks identical to existing member %q — pick a name that can be told apart", name, m.Name)
		}
		if m.Name != name && m.SignKey == signKey {
			return fmt.Errorf("signing key already belongs to %q — each member needs their own keys", m.Name)
		}
	}
	return Save(members)
}

// Remove deletes a member by name and persists the list. Removing someone only
// takes effect once `push` re-encrypts without them.
func Remove(name string) error {
	members, err := Load()
	if err != nil {
		return err
	}
	for i, m := range members {
		if m.Name == name {
			return Save(append(members[:i], members[i+1:]...))
		}
	}
	return fmt.Errorf("no member named %q in %s", name, Path)
}

// validateName rejects names that would corrupt the line-oriented recipients
// file or deceive whoever reads it: whitespace (a newline could smuggle in an
// entire extra recipient line), a leading '#' (would comment the entry out),
// and any non-graphic rune. The non-graphic test rejects both control
// characters (category Cc — ANSI escapes that could rewrite the prompts that
// display the name) and format characters (category Cf — zero-width and bidi
// runes that render invisibly). This file arrives over an untrusted channel (a
// clone, a merge), so a Cf-spoofed name could forge a visual duplicate of an
// existing member — and duplicate-name detection is by exact string, so the
// forgery would slip past it and let a shadow entry hijack that member's
// signature attribution.
//
// IsGraphic alone still admits runes that render as nothing: variation
// selectors and the combining grapheme joiner (category Mn), Hangul fillers
// (Lo), and the blank braille pattern (So). Those are rejected explicitly, as
// is a leading combining mark, which has no base letter to attach to and would
// otherwise decorate whatever precedes the name on screen.
//
// The errors never quote the name: on Load it is untrusted input that has, by
// definition, failed validation, and may carry terminal escapes.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("member name must not be empty")
	}
	if utf8.RuneCountInString(name) > maxNameLen {
		return fmt.Errorf("member name must not be longer than %d characters", maxNameLen)
	}
	if strings.HasPrefix(name, "#") {
		return fmt.Errorf("member name must not start with '#'")
	}
	if first, _ := utf8.DecodeRuneInString(name); unicode.Is(unicode.M, first) {
		return fmt.Errorf("member name must not start with a combining mark")
	}
	for _, r := range name {
		// IsSpace is checked separately because a plain space (U+0020) is a
		// graphic rune, yet still splits the line into the wrong number of fields.
		if unicode.IsSpace(r) || !unicode.IsGraphic(r) || invisible(r) {
			return fmt.Errorf("member name must not contain whitespace, control, or invisible characters")
		}
	}
	return nil
}

// invisible reports graphic runes that render as blank space or nothing at
// all. Default_Ignorable_Code_Point is Cf (already non-graphic) plus these two
// properties; U+2800 is not default-ignorable but is drawn as an empty cell.
func invisible(r rune) bool {
	return unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		unicode.Is(unicode.Variation_Selector, r) ||
		r == '⠀'
}

// maxNameLen bounds member names: they are printed in every prompt, and nothing
// legitimate needs a name that scrolls the prompt off the screen.
const maxNameLen = 64

// lookalikes maps Cyrillic and Greek letters that render like a Latin letter
// to that letter. It is deliberately small — the letters that are
// indistinguishable in common terminal fonts — not a full Unicode confusables
// table, which the standard library does not carry.
var lookalikes = map[rune]rune{
	'а': 'a', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'һ': 'h', 'і': 'i', 'ј': 'j', 'к': 'k',
	'о': 'o', 'р': 'p', 'ԛ': 'q', 'ѕ': 's', 'ԝ': 'w', 'х': 'x', 'у': 'y',
	'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
	'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'У': 'Y',
	'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'ι': 'i', 'κ': 'k',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
	'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

// skeleton reduces a name to what it looks like, so two names that differ only
// in lookalike characters compare equal. Genuinely different names — including
// non-Latin ones — keep distinct skeletons, so no script is forbidden; only
// impersonation is. The steps, in order:
//
//   - NFKC folds compatibility forms: fullwidth and mathematical alphanumerics
//     (𝚊𝚕𝚒𝚌𝚎), ligatures, superscripts.
//   - The lookalike table runs before case folding, because an uppercase
//     Cyrillic or Greek letter resembles an uppercase Latin one (В/B) while the
//     lowercase forms differ (в/b).
//   - Case folding: "Alice" and "alice" are the same person to a reader.
//   - NFD then dropping every combining mark: an accent is easy to miss in a
//     prompt, so "alicé" is treated as "alice". The table runs once more so a
//     decomposed Cyrillic letter (ё → е + ̈) lands on its Latin twin.
//
// Known limits: this is not the full Unicode confusables table (the standard
// library does not carry it), so letters that merely resemble a different
// Latin letter — Armenian ա (≈ w), Cherokee, or Latin dotless ı — are not
// folded. Invisible runes are not handled here; validateName rejects them.
func skeleton(name string) string {
	s := norm.NFKC.String(name)
	s = strings.Map(lookalike, s)
	s = cases.Fold().String(s)
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.M, r) {
			return -1
		}
		return lookalike(r)
	}, norm.NFD.String(s))
	return s
}

func lookalike(r rune) rune {
	if l, ok := lookalikes[r]; ok {
		return l
	}
	return r
}

// Keys parses every member into an age.Recipient for encryption.
func Keys(members []Member) ([]age.Recipient, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("no recipients — add at least one with `shenv add-member`")
	}
	recipients := make([]age.Recipient, 0, len(members))
	for _, m := range members {
		r, err := age.ParseX25519Recipient(m.Key)
		if err != nil {
			return nil, fmt.Errorf("recipient %q has an invalid key: %w", m.Name, err)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}
