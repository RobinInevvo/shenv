package update

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// latestServer fakes GitHub's /releases/latest returning tag, with no assets:
// the pre-release gate must decide before any asset is looked up.
func latestServer(t *testing.T, tag string) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/p-arndt/shenv/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Release{Tag: tag})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &Client{HTTP: srv.Client(), APIBase: srv.URL, Owner: "p-arndt", Repo: "shenv"}
}

func TestPrereleaseAllowed(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"0.9.0", "0.8.1", true},
		{"0.9.0-rc1", "0.8.1", false},
		{"v0.9.0-rc1", "0.8.1", false},
		{"0.9.0-rc2", "0.9.0-rc1", true},
		{"0.9.0", "0.9.0-rc1", true},
		{"0.9.0+build.5", "0.8.1", true}, // build metadata is not a pre-release
	}
	for _, c := range cases {
		if got := prereleaseAllowed(c.latest, c.current); got != c.want {
			t.Errorf("prereleaseAllowed(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestSelfUpdateSkipsPrereleaseOnStable(t *testing.T) {
	for _, checkOnly := range []bool{false, true} {
		c := latestServer(t, "v0.9.0-rc1")
		res, err := c.SelfUpdate(context.Background(), "0.8.1", checkOnly)
		if err != nil {
			t.Fatalf("checkOnly=%v: a skipped pre-release must not be an error: %v", checkOnly, err)
		}
		if res.Updated || IsNewer(res.Latest, res.Current) {
			t.Fatalf("checkOnly=%v: stable build accepted pre-release latest: %+v", checkOnly, res)
		}
		if res.SkippedPrerelease != "0.9.0-rc1" {
			t.Errorf("checkOnly=%v: SkippedPrerelease = %q, want 0.9.0-rc1", checkOnly, res.SkippedPrerelease)
		}
	}
}

func TestSelfUpdateAllowsNewerPrereleaseOnPrerelease(t *testing.T) {
	c := latestServer(t, "v0.9.0-rc2")
	res, err := c.SelfUpdate(context.Background(), "0.9.0-rc1", true)
	if err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	if res.Latest != "0.9.0-rc2" || !IsNewer(res.Latest, res.Current) {
		t.Errorf("expected rc2 to be offered, got %+v", res)
	}
}

func TestSelfUpdateCheckStableUnchanged(t *testing.T) {
	c := latestServer(t, "v0.9.0")
	res, err := c.SelfUpdate(context.Background(), "0.8.1", true)
	if err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	if res.Updated || res.Latest != "0.9.0" || !IsNewer(res.Latest, res.Current) {
		t.Errorf("unexpected check result %+v", res)
	}
}

// An older pre-release as "latest" is a no-op, not an error: there is nothing
// to skip when it wouldn't be an update anyway.
func TestSelfUpdateIgnoresOlderPrerelease(t *testing.T) {
	c := latestServer(t, "v0.8.0-rc1")
	res, err := c.SelfUpdate(context.Background(), "0.8.1", false)
	if err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	if res.Updated {
		t.Error("older pre-release must not be installed")
	}
}

func TestNotifySilentForPrereleaseOnStable(t *testing.T) {
	seedState(t, state{LastCheck: time.Now(), Latest: "0.9.0-rc1"})
	t.Setenv("SHENV_NO_UPDATE_CHECK", "")
	var buf bytes.Buffer
	NotifyIfAvailable(&buf, "0.8.1")
	if buf.Len() != 0 {
		t.Errorf("stable build must not be told about a pre-release, got %q", buf.String())
	}
}

func TestNotifyAnnouncesPrereleaseOnPrerelease(t *testing.T) {
	seedState(t, state{LastCheck: time.Now(), Latest: "0.9.0-rc2"})
	t.Setenv("SHENV_NO_UPDATE_CHECK", "")
	var buf bytes.Buffer
	NotifyIfAvailable(&buf, "0.9.0-rc1")
	if !strings.Contains(buf.String(), "0.9.0-rc2") {
		t.Errorf("expected a hint mentioning 0.9.0-rc2, got %q", buf.String())
	}
}
