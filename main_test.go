package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	project, key, err := parseRef("bws://QA/api-key")
	if err != nil || project != "QA" || key != "api-key" {
		t.Fatalf("got %q %q err=%v", project, key, err)
	}
	for _, ref := range []string{"", "bws://", "bws://only-project", "op://Dev/Item/Field", "bws://a/b/c"} {
		if _, _, err := parseRef(ref); err == nil {
			t.Fatalf("%q should not parse", ref)
		}
	}
}

type staticVendor struct {
	value string
	err   error
}

func (s *staticVendor) item(_ context.Context, _, _ string) (string, error) { return s.value, s.err }
func (s *staticVendor) items(_ context.Context) ([]sourceItem, error) {
	return []sourceItem{}, nil
}

func serve(t *testing.T, v vendor, secret string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+resolvePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PiCode-Proxy-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in struct {
			Ref string `json:"ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Ref == "" {
			answer(w, &resolveError{class: errMissing, detail: "no reference"})
			return
		}
		project, key, err := parseRef(in.Ref)
		if err != nil {
			answer(w, &resolveError{class: errMissing, detail: clip(err.Error())})
			return
		}
		value, err := v.item(context.Background(), project, key)
		if err != nil {
			answer(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestResolveContract(t *testing.T) {
	ts := serve(t, &staticVendor{value: "bw-live-7"}, "k")
	req, err := http.NewRequest("POST", ts.URL+resolvePath, strings.NewReader(`{"ref":"bws://QA/api-key"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-PiCode-Proxy-Secret", "k")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(res.Body).Decode(&out)
	if len(out) != 1 || out["value"] != "bw-live-7" {
		t.Fatalf("value: %#v", out)
	}

	req2, err := http.NewRequest("POST", ts.URL+resolvePath, strings.NewReader(`{"ref":"bws://a/b"}`))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("X-PiCode-Proxy-Secret", "wrong")
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong secret: %d", res2.StatusCode)
	}
}

func TestClassesMapToStatuses(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
	}{
		"revoked":     {&resolveError{class: errRevoked}, http.StatusConflict},
		"forbidden":   {&resolveError{class: errForbidden}, http.StatusForbidden},
		"missing":     {&resolveError{class: errMissing}, http.StatusNotFound},
		"unavailable": {&resolveError{class: errUnavailable}, http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		ts := serve(t, &staticVendor{err: tc.err}, "k")
		req, _ := http.NewRequest("POST", ts.URL+resolvePath, strings.NewReader(`{"ref":"bws://a/b"}`))
		req.Header.Set("X-PiCode-Proxy-Secret", "k")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("%s: %d", name, res.StatusCode)
		}
	}
}

func TestFakeVendorFixture(t *testing.T) {
	path := t.TempDir() + "/fixture.json"
	fixture := `{"refs": {"bws://QA/api-key": "bw-test"}, "items": [{"ref": "bws://QA/api-key", "label": "api-key", "vault": "QA"}]}`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := newFakeVendor(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.item(context.Background(), "QA", "api-key")
	if err != nil || got != "bw-test" {
		t.Fatalf("fake resolve: %q %v", got, err)
	}
}
