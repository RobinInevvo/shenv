package command

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"filippo.io/age"

	"shenv/internal/backend"
	"shenv/internal/crypto"
	"shenv/internal/recipients"
	"shenv/internal/style"
)

// loadBackend resolves the configured backend and, for an exec backend, ensures
// its shell commands have been approved for this repo before they can run. See
// backend.EnsureTrusted for why this gate exists.
func loadBackend() (backend.Backend, error) {
	store, err := backend.Load()
	if err != nil {
		return nil, err
	}
	if err := backend.EnsureTrusted(store, confirmExec); err != nil {
		return nil, err
	}
	return store, nil
}

// confirmExec shows the exec backend's commands and asks the user to approve them.
func confirmExec(getCmd, putCmd string) (bool, error) {
	fmt.Println("This repo's config.shenv uses an EXEC backend, which runs shell commands:")
	// Sanitize even though readConfig already rejects control characters: this
	// prompt is the sole gate before arbitrary code execution, so its display
	// must not depend on every upstream path staying escape-free.
	if getCmd != "" {
		fmt.Printf("    get: %s\n", sanitizeTerm(getCmd))
	}
	if putCmd != "" {
		fmt.Printf("    put: %s\n", sanitizeTerm(putCmd))
	}
	fmt.Println(style.Warn("These come from the repo and could have been added by anyone with commit access."))
	return askYesNo("Run them?"), nil
}

// stateDir is the per-user shenv directory that holds local trust/bookkeeping
// state. It lives outside any repo so a hostile repo can't tamper with it.
func stateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".shenv", "state"), nil
}

// pushedRecipientsPath is where the recipient set from this repo's last seal is
// recorded, keyed by the absolute recipients-file path so repos don't collide.
func pushedRecipientsPath() (string, error) {
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(recipients.Path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".recipients"), nil
}

// confirmNoLockout compares the members embedded in the current blob (who can
// decrypt today) against the set about to be encrypted for, and turns a silent
// lockout into a blocking prompt. Unlike confirmRecipients this needs no local
// state — the truth travels inside the blob — so it protects against drift that
// happened on any machine. A blob that exists but can't be decrypted with this
// identity gets its own warning: overwriting a blob you can't read likely locks
// out everyone who can. A blob whose signature can't be verified gets one too:
// its manifest can't be trusted, so the lockout comparison is skipped.
func confirmNoLockout(store backend.Backend, cur []recipients.Member, id age.Identity) (bool, error) {
	prevBlob, err := store.Get()
	if errors.Is(err, backend.ErrNotFound) {
		return true, nil // no existing blob — first seal, nothing to guard
	}
	if err != nil {
		// A denied, failed, or oversized read is not an absent blob: a backend can
		// refuse reads and still accept writes, and proceeding would overwrite a
		// blob whose members were never compared — the exact silent lockout this
		// guard exists to prevent.
		return false, fmt.Errorf("cannot read the existing blob from %s, so the lockout check cannot run (an exec `get` must exit 0 with empty output when nothing is stored yet): %w", store, err)
	}

	payload, err := crypto.DecryptBytes(prevBlob, id)
	if err != nil {
		fmt.Println("An encrypted env.shenv already exists, but your key cannot decrypt it.")
		fmt.Println(style.Danger("Overwriting it would likely LOCK OUT everyone who can read it today."))
		fmt.Println("If you are new here, ask a member to run `shenv add-member` with your key instead.")
		return askYesNo("Overwrite anyway?"), nil
	}
	// This decrypt of the previous blob exists only to read its manifest, but it
	// also brings the old .env plaintext into memory; zero it once the guard is done.
	defer crypto.Zero(payload)

	// The manifest is only as trustworthy as its signature: the recipient keys
	// are public, so anyone who can write to the backend could plant a
	// decryptable blob with a fabricated member list and steer — or suppress —
	// the lockout warning. Verify before trusting it; on failure the guard
	// degrades to a blunt overwrite prompt. Legitimate paths land here too (a
	// blob from a pre-signing shenv, a last sealer who has since been removed),
	// hence the soft wording.
	_, body, err := verifiedBody(payload, true)
	if err != nil {
		fmt.Println(style.Warn("The existing env.shenv can't be verified, so who can decrypt it today is"))
		fmt.Println(style.Warn("unknown and the lockout check is skipped:"))
		fmt.Printf("    %v\n", err)
		return askYesNo("Overwrite it?"), nil
	}
	// body is a fresh copy of the decrypted payload (ExtractSignature allocates),
	// so it needs its own wipe; the plaintext half of the manifest split is
	// unused here and can be dropped immediately.
	defer crypto.Zero(body)
	prev, prevEnv := recipients.ExtractManifest(body)
	crypto.Zero(prevEnv)
	if len(prev) == 0 {
		return true, nil // defensive: a signed blob always carries a manifest
	}

	curKeys := make(map[string]bool, len(cur))
	for _, m := range cur {
		curKeys[m.Key] = true
	}
	var dropped []recipients.Member
	for _, m := range prev {
		if !curKeys[m.Key] {
			dropped = append(dropped, m)
		}
	}
	if len(dropped) == 0 {
		return true, nil
	}

	fmt.Println(style.Danger("These members can decrypt the current env.shenv but are MISSING from " + recipients.Path + ":"))
	for _, m := range dropped {
		fmt.Printf("    %s %s  %s\n", style.Danger("-"), sanitizeTerm(m.Name), sanitizeTerm(m.Key))
	}
	fmt.Println(style.Danger("Pushing now will LOCK THEM OUT.") + " If that is unintended, restore them with")
	fmt.Println("`shenv add-member` (or `git checkout " + recipients.Path + "`) first.")
	fmt.Println("To revoke access on purpose, use `shenv remove-member` and confirm here.")
	return askYesNo("Lock them out?"), nil
}

// confirmRecipients lists the members the secrets are about to be encrypted for and,
// if that set changed since this machine's last seal, shows the additions/removals
// and asks the user to confirm. This turns a silent recipient injection into a
// visible, blocking prompt. selfKey is the user's own public key (may be empty);
// on the very first seal from a machine, any recipient beyond it must also be
// confirmed — the list comes from the repo, so a fresh clone could otherwise
// exfiltrate to a planted key with no prompt at all. Returns true to proceed.
func confirmRecipients(members []recipients.Member, selfKey string) (bool, error) {
	fmt.Println(style.Header(fmt.Sprintf("Encrypting for %d recipient(s):", len(members))))
	for _, m := range members {
		fmt.Printf("    %s  %s\n", m.Name, style.Dim(m.Key))
	}

	project, err := backend.Project()
	if err != nil {
		return false, err
	}
	prev, err := loadPin(project)
	if err != nil {
		return false, err
	}
	if prev == nil {
		for _, m := range members {
			if m.Key != selfKey {
				fmt.Println("\n" + style.Warn("First seal from this machine — the recipient list above comes from the repo."))
				fmt.Println(style.Warn("Anyone listed will be able to decrypt these secrets."))
				return askYesNo("Continue?"), nil
			}
		}
		return true, nil // first seal, but only encrypting for yourself
	}

	added, removed := recipientDiff(prev.members, recipientSet(members))
	membersChanged := len(added) > 0 || len(removed) > 0
	projectChanged := prev.project != project
	if !membersChanged && !projectChanged {
		return true, nil
	}

	if membersChanged {
		fmt.Println("\n" + style.Warn("The recipient list CHANGED since your last seal:"))
		printMemberDiff(os.Stdout, added, removed)
		fmt.Println(style.Warn("Anyone added here will be able to decrypt these secrets."))
	}
	if projectChanged {
		fmt.Println("\n" + style.Warn("The project id in config.shenv CHANGED since your last seal:"))
		printProjectChange(os.Stdout, prev.project, project)
		fmt.Println(style.Warn("The blob will be bound to the new id and verify only where config.shenv names it."))
	}
	return askYesNo("Continue?"), nil
}

// printMemberDiff renders the member entries that changed against the pin.
// Sanitized for the same reason as confirmExec: this prompt is what exposes a
// planted recipient, so it must render exactly what the file contains.
// Additions render in warning yellow, not success green: their job is to expose
// a possibly-planted key, so they must read as an alarm.
func printMemberDiff(w io.Writer, added, removed []string) {
	for _, a := range added {
		fmt.Fprintln(w, style.Warn("    + "+sanitizeTerm(strings.ReplaceAll(a, "\t", "  "))))
	}
	for _, r := range removed {
		fmt.Fprintln(w, style.Danger("    - "+sanitizeTerm(strings.ReplaceAll(r, "\t", "  "))))
	}
}

// printProjectChange renders a changed project id. An empty id is an absent
// `project` line, which counts as a change too: it lets open accept unbound
// blobs again.
func printProjectChange(w io.Writer, from, to string) {
	label := func(id string) string {
		if id == "" {
			return "(none)"
		}
		return sanitizeTerm(id)
	}
	fmt.Fprintln(w, style.Danger("    project: "+label(from)+" → "+label(to)))
}

// recipientDiff lists the entries that appeared and disappeared between two
// recipient sets, sorted for stable output.
func recipientDiff(prev, cur map[string]bool) (added, removed []string) {
	for k := range cur {
		if !prev[k] {
			added = append(added, k)
		}
	}
	for k := range prev {
		if !cur[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// confirmPinnedRecipients guards the read side the way confirmRecipients guards
// seal. open, run and edit verify the blob against the signing keys in
// recipients.shenv, which arrives over the same untrusted channel as the blob:
// whoever can change both can add their own key and sign whatever they like. So
// the set this machine last accepted is pinned, and a changed file has to be
// confirmed before its keys are trusted. The project id signatures are bound to
// comes from the repo too and is pinned alongside. The pin is the one seal records — a
// change confirmed on either side is not asked about again on the other.
//
// Everything goes to stderr: `shenv run` hands stdout to the child's consumer.
func confirmPinnedRecipients() error {
	members, err := recipients.Load()
	if err != nil || len(members) == 0 {
		return err // an empty list fails verification on its own
	}
	project, err := backend.Project()
	if err != nil {
		return err
	}
	prev, err := loadPin(project)
	if err != nil {
		return err
	}
	if prev == nil {
		// Nothing to compare a first use against; trust on first use, and say so.
		fmt.Fprintf(os.Stderr, "Trusting the %d member(s) in %s from now on; later changes will need confirmation.\n", len(members), recipients.Path)
		return rememberRecipients(members)
	}
	added, removed := recipientDiff(prev.members, recipientSet(members))
	membersChanged := len(added) > 0 || len(removed) > 0
	projectChanged := prev.project != project
	if !membersChanged && !projectChanged {
		return nil
	}

	var changed []string
	if membersChanged {
		changed = append(changed, recipients.Path)
		fmt.Fprintln(os.Stderr, style.Warn(recipients.Path+" CHANGED since this machine last trusted it:"))
		printMemberDiff(os.Stderr, added, removed)
		fmt.Fprintln(os.Stderr, style.Warn("A blob signed by anyone added here will be accepted as genuine."))
	}
	if projectChanged {
		changed = append(changed, "the project id in config.shenv")
		fmt.Fprintln(os.Stderr, style.Warn("The project id in config.shenv CHANGED since this machine last trusted it:"))
		printProjectChange(os.Stderr, prev.project, project)
		fmt.Fprintln(os.Stderr, style.Warn("A blob a shared member sealed for that project will be accepted as genuine."))
	}
	if os.Getenv("SHENV_TRUST_RECIPIENTS") == "1" {
		fmt.Fprintln(os.Stderr, "shenv: SHENV_TRUST_RECIPIENTS=1 — accepting the change without asking")
		return rememberRecipients(members)
	}
	question := "Trust the new member list?"
	if !membersChanged {
		question = "Trust the new project id?"
	} else if projectChanged {
		question = "Trust these changes?"
	}
	fmt.Fprint(os.Stderr, "\n"+style.Prompt(question+" [y/N]")+" ")
	if !confirm() {
		return fmt.Errorf("%s changed and was not confirmed — refusing to verify env.shenv against it", strings.Join(changed, " and "))
	}
	return rememberRecipients(members)
}

// sanitizeTerm strips non-graphic runes from strings that reach the terminal.
// The dropped-member list comes from a decrypted manifest — signed, but possibly
// by a malicious member — and a name or key carrying ANSI escape bytes could
// otherwise rewrite the very prompt that is supposed to expose the tampering.
// Format runes (bidi overrides, zero-width characters) are not control
// characters but reorder or hide what is displayed just the same.
func sanitizeTerm(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsGraphic(r) {
			return -1
		}
		return r
	}, s)
}

// projectPinPrefix marks the pin's project-id line. Member names can't start
// with '#', so it can't be mistaken for a member entry.
const projectPinPrefix = "#project\t"

// pin is what this machine last accepted for a checkout: the member set and the
// project id signatures are bound to. Both come from the repo and both decide
// what open accepts — a swapped project id lets a blob a shared member sealed
// for another repo verify here — so a change to either has to be confirmed.
type pin struct {
	members map[string]bool
	project string
}

// rememberRecipients records the recipient set and the current project id after
// a successful seal or a confirmed change, so the next run can detect changes.
func rememberRecipients(members []recipients.Member) error {
	project, err := backend.Project()
	if err != nil {
		return err
	}
	return writePin(recipientSet(members), project)
}

func writePin(members map[string]bool, project string) error {
	path, err := pushedRecipientsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	lines := make([]string, 0, len(members)+1)
	for k := range members {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	lines = append(lines, projectPinPrefix+project)
	// Written atomically: a half-written set would look like a recipient change on
	// the next seal — or, worse, hide one — and this file is the only record of
	// what this machine last sealed for.
	return backend.WriteFileAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// loadPin reads this checkout's pin, or nil when there is none yet. A pin
// written before the project id was pinned adopts the current one silently and
// is rewritten: prompting would break every non-interactive run on upgrade, and
// adopting is the same trust on first use a fresh machine gets.
func loadPin(project string) (*pin, error) {
	p, hasProject, err := readPin()
	if err != nil || p == nil {
		return nil, err
	}
	if !hasProject {
		p.project = project
		if err := writePin(p.members, project); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// loadPushedRecipients reads the member set from the last seal. The second
// result is false when no previous seal has been recorded on this machine.
func loadPushedRecipients() (map[string]bool, bool, error) {
	p, _, err := readPin()
	if err != nil || p == nil {
		return nil, false, err
	}
	return p.members, true, nil
}

// readPin parses the pin file as written, reporting whether it carries a
// project line; nil means no pin exists yet.
func readPin() (*pin, bool, error) {
	path, err := pushedRecipientsPath()
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	p := &pin{members: map[string]bool{}}
	hasProject := false
	for line := range strings.SplitSeq(string(data), "\n") {
		// Trim only the line ending: entries are tab-separated and a member
		// without a sign key ends in a tab that TrimSpace would eat.
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, projectPinPrefix):
			p.project, hasProject = strings.TrimPrefix(line, projectPinPrefix), true
		case strings.TrimSpace(line) != "":
			p.members[line] = true
		}
	}
	return p, hasProject, nil
}

// recipientSet builds a comparable set of "name\tkey\tsignkey" entries, so a
// swapped key, a renamed member, or a replaced signing key all register as a
// change. The signing key matters as much as the encryption key: open trusts it
// to verify who sealed, so swapping it in recipients.shenv would let an attacker
// forge blobs "signed by" an existing member — that edit must hit this prompt.
func recipientSet(members []recipients.Member) map[string]bool {
	set := make(map[string]bool, len(members))
	for _, m := range members {
		set[m.Name+"\t"+m.Key+"\t"+m.SignKey] = true
	}
	return set
}
