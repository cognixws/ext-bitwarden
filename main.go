// Command picode-bitwarden is the Bitwarden Secrets Manager secret-source
// process for COGNIX[WS] (ADR-0388, door L of ADR-0109). The daemon starts
// it while the extension is on; it answers one resolve call over loopback
// and publishes the names of the secrets it can see. A value exists in
// memory between the vendor's answer and the resolve response, and nowhere
// else: nothing is written, cached to disk, logged or sent to the host.
//
// Bitwarden Secrets Manager's machine-account access token authenticates
// directly as a Bearer token on api.bitwarden.com, so this process needs no
// SDK: the Go standard library covers every call.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const resolvePath = "/picode/vault/resolve"

const (
	errRevoked     = "revoked"
	errForbidden   = "forbidden"
	errMissing     = "missing"
	errUnavailable = "unavailable"
)

// apiBase answers the Secrets Manager API for the account's cloud region.
func apiBase(region string) string {
	if strings.EqualFold(strings.TrimSpace(region), "eu") {
		return "https://api.bitwarden.eu"
	}
	return "https://api.bitwarden.com"
}

type resolveError struct {
	class  string
	detail string
}

func (e *resolveError) Error() string { return e.class + ": " + e.detail }

func (e *resolveError) status() int {
	switch e.class {
	case errRevoked:
		return http.StatusConflict
	case errForbidden:
		return http.StatusForbidden
	case errMissing:
		return http.StatusNotFound
	default:
		return http.StatusServiceUnavailable
	}
}

// vendor is the one seam tests fake.
type vendor interface {
	item(ctx context.Context, project, key string) (string, error)
	items(ctx context.Context) ([]sourceItem, error)
}

type sourceItem struct {
	Ref   string `json:"ref"`
	Label string `json:"label"`
	Vault string `json:"vault"`
}

type host struct{ url, token string }

type publisher interface{ publishLoop(h host) }

func main() {
	log.SetFlags(0)
	port := os.Getenv("PICODE_EXT_PORT")
	secret := os.Getenv("PICODE_EXT_PROXY_SECRET")
	hostURL := strings.TrimRight(os.Getenv("PICODE_URL"), "/")
	extToken := os.Getenv("PICODE_EXT_TOKEN")
	if port == "" || secret == "" {
		log.Fatal("this process runs supervised by COGNIX[WS]; start it from the extension, not by hand")
	}

	var v vendor
	if fake := os.Getenv("EXT_1PASSWORD_FAKE"); fake != "" {
		if os.Getenv("EXT_QA_MODE") != "1" {
			log.Fatal("the fixture resolver answers fake values and runs only with EXT_QA_MODE=1")
		}
		fv, err := newFakeVendor(fake)
		if err != nil {
			log.Fatal(err)
		}
		v = fv
		log.Printf("QA fixture resolver on %s", fake)
	} else {
		v = &bitwardenVendor{h: host{url: hostURL, token: extToken}, region: "us"}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+resolvePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PiCode-Proxy-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in struct {
			Ref string `json:"ref"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil || in.Ref == "" {
			answer(w, &resolveError{class: errMissing, detail: "the resolve call carried no reference"})
			return
		}
		project, key, err := parseRef(in.Ref)
		if err != nil {
			answer(w, &resolveError{class: errMissing, detail: clip(err.Error())})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		value, err := v.item(ctx, project, key)
		if err != nil {
			answer(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
	})
	mux.HandleFunc("GET /picode/vault/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PiCode-Proxy-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	if pub, ok := v.(publisher); ok && hostURL != "" && extToken != "" {
		go pub.publishLoop(host{url: hostURL, token: extToken})
	}

	log.Printf("Bitwarden source listening on 127.0.0.1:%s", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func answer(w http.ResponseWriter, err error) {
	re, ok := err.(*resolveError)
	if !ok {
		re = &resolveError{class: errUnavailable, detail: clip(err.Error())}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(re.status())
	_ = json.NewEncoder(w).Encode(map[string]string{"class": re.class, "detail": re.detail})
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

var errBadRef = errors.New("a reference reads bws://<project>/<secret-key>")

func parseRef(ref string) (project, key string, err error) {
	rest, ok := strings.CutPrefix(ref, "bws://")
	if !ok {
		return "", "", errBadRef
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", errBadRef
	}
	return parts[0], parts[1], nil
}

// bitwardenVendor speaks the Secrets Manager REST API with the access token
// as a Bearer. The caches hold names and ids only; a value is fetched per
// resolve and never stored.
type bitwardenVendor struct {
	region string
	h      host
	mu     sync.Mutex
	// accessToken tracks what the caches were built with.
	accessToken string
	projects    map[string]string // name -> id
	projectIDs  map[string]string // id -> name
	secrets     map[string]map[string]string
	cacheAt     time.Time
	client      *http.Client
}

func (o *bitwardenVendor) httpClient() *http.Client {
	if o.client != nil {
		return o.client
	}
	return http.DefaultClient
}

// token reads the machine account's access token from the host's sealed
// settings. It stays in this process's memory.
func (o *bitwardenVendor) token(ctx context.Context) (string, error) {
	if o.accessToken != "" {
		return o.accessToken, nil
	}
	if o.h.url == "" || o.h.token == "" {
		return "", &resolveError{class: errForbidden, detail: "no access token is set; connect on the extension's page"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.h.url+"/api/ext/v1/settings", nil)
	if err != nil {
		return "", &resolveError{class: errUnavailable}
	}
	req.Header.Set("X-PiCode-Extension-Token", o.h.token)
	res, err := o.httpClient().Do(req)
	if err != nil {
		return "", &resolveError{class: errUnavailable}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", &resolveError{class: errUnavailable}
	}
	var out struct {
		Settings map[string]any `json:"settings"`
	}
	if json.NewDecoder(res.Body).Decode(&out) != nil {
		return "", &resolveError{class: errUnavailable}
	}
	t, _ := out.Settings["access_token"].(string)
	if region, _ := out.Settings["region"].(string); region != "" && region != o.region {
		o.region = region
		o.accessToken = ""
		o.projects, o.projectIDs, o.secrets = nil, nil, nil
		o.cacheAt = time.Time{}
	}
	if t == "" {
		return "", &resolveError{class: errForbidden, detail: "no access token is set; connect on the extension's page"}
	}
	o.accessToken = t
	return t, nil
}

func (o *bitwardenVendor) get(ctx context.Context, path string, out any) error {
	token, err := o.token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase(o.region)+path, nil)
	if err != nil {
		return &resolveError{class: errUnavailable}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := o.httpClient().Do(req)
	if err != nil {
		return &resolveError{class: errUnavailable, detail: "Bitwarden did not answer"}
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		if err != nil || json.Unmarshal(body, out) != nil {
			return &resolveError{class: errUnavailable, detail: "the answer could not be read"}
		}
		return nil
	case res.StatusCode == http.StatusUnauthorized:
		return &resolveError{class: errRevoked, detail: "the access token was refused; connect again"}
	case res.StatusCode == http.StatusForbidden:
		return &resolveError{class: errForbidden, detail: "the machine account cannot reach this project or secret"}
	case res.StatusCode == http.StatusNotFound:
		return &resolveError{class: errMissing, detail: "the project or secret is not there (or is not shared)"}
	default:
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return &resolveError{class: errUnavailable, detail: clip(fmt.Sprintf("%d %s", res.StatusCode, raw))}
	}
}

// connect resets the caches when the token changed (the publish loop's job).
func (o *bitwardenVendor) connect(token string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.accessToken == token && o.projects != nil {
		return
	}
	o.accessToken = token
	o.projects, o.projectIDs, o.secrets = nil, nil, nil
	o.cacheAt = time.Time{}
	log.Printf("connected to Bitwarden Secrets Manager")
}

func (o *bitwardenVendor) ensureCache(ctx context.Context) error {
	o.mu.Lock()
	if time.Since(o.cacheAt) < time.Minute && o.projects != nil {
		o.mu.Unlock()
		return nil
	}
	o.mu.Unlock()

	var projects []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := o.get(ctx, "/projects", &projects); err != nil {
		return err
	}
	byName, byID := map[string]string{}, map[string]string{}
	secrets := map[string]map[string]string{}
	for _, p := range projects {
		byName[strings.ToLower(p.Name)] = p.ID
		byID[p.ID] = p.Name
		var list struct {
			Secrets []struct {
				ID  string `json:"id"`
				Key string `json:"key"`
			} `json:"secrets"`
		}
		if err := o.get(ctx, "/projects/"+url.PathEscape(p.ID)+"/secrets", &list); err != nil {
			continue
		}
		byKey := map[string]string{}
		for _, s := range list.Secrets {
			byKey[strings.ToLower(s.Key)] = s.ID
		}
		secrets[p.ID] = byKey
	}
	o.mu.Lock()
	o.projects, o.projectIDs, o.secrets, o.cacheAt = byName, byID, secrets, time.Now()
	o.mu.Unlock()
	return nil
}

func (o *bitwardenVendor) item(ctx context.Context, project, key string) (string, error) {
	if err := o.ensureCache(ctx); err != nil {
		return "", err
	}
	o.mu.Lock()
	projectID := o.projects[strings.ToLower(project)]
	if projectID == "" {
		projectID = project // an ID was named directly
	}
	projectName := o.projectIDs[projectID]
	secretID := o.secrets[projectID][strings.ToLower(key)]
	o.mu.Unlock()
	if secretID == "" {
		return "", &resolveError{class: errMissing, detail: fmt.Sprintf("there is no secret %q in project %q", key, projectName)}
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := o.get(ctx, "/secrets/"+url.PathEscape(secretID), &out); err != nil {
		return "", err
	}
	if out.Value == "" {
		return "", &resolveError{class: errMissing, detail: fmt.Sprintf("the secret %q is empty", key)}
	}
	return out.Value, nil
}

func (o *bitwardenVendor) items(ctx context.Context) ([]sourceItem, error) {
	if err := o.ensureCache(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	out := []sourceItem{}
	for projectID, byKey := range o.secrets {
		projectName := o.projectIDs[projectID]
		for key := range byKey {
			out = append(out, sourceItem{Ref: fmt.Sprintf("bws://%s/%s", projectName, key), Label: key, Vault: projectName})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

// publishLoop keeps the tab's names current: read the access token back
// from the sealed settings, and republish whenever it changed or the cache
// expired.
func (o *bitwardenVendor) publishLoop(h host) {
	for {
		if token, err := o.token(context.Background()); err == nil && token != "" {
			o.connect(token)
			if items, err := o.items(context.Background()); err == nil {
				publishItems(h, items)
			} else {
				log.Printf("publish: %v", err)
			}
		}
		time.Sleep(30 * time.Second)
	}
}

func publishItems(h host, items []sourceItem) {
	if len(items) > 500 {
		items = items[:500]
	}
	body, _ := json.Marshal(map[string]any{"items": items})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url+"/api/ext/v1/vaults/items", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("X-PiCode-Extension-Token", h.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("publish: %v", err)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("publish: %d", res.StatusCode)
		return
	}
	log.Printf("published %d secret names", len(items))
}

// fakeVendor answers from a JSON fixture. QA only: main refuses to start it
// without EXT_QA_MODE=1.
type fakeVendor struct {
	refs     map[string]string
	itemList []sourceItem
}

func newFakeVendor(path string) (vendor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Refs  map[string]string `json:"refs"`
		Items []sourceItem      `json:"items"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &fakeVendor{refs: f.Refs, itemList: f.Items}, nil
}

func (f *fakeVendor) item(_ context.Context, project, key string) (string, error) {
	v, ok := f.refs[fmt.Sprintf("bws://%s/%s", project, key)]
	if !ok {
		return "", &resolveError{class: errMissing, detail: fmt.Sprintf("the fixture has no %s/%s", project, key)}
	}
	return v, nil
}

func (f *fakeVendor) items(_ context.Context) ([]sourceItem, error) { return f.itemList, nil }

// The publish loop's shared helper lives beside the process's other doors.
var _ = errors.New
