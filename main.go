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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
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
	// A login (Password Manager) names the sites it signs in to.
	Kind  string   `json:"kind,omitempty"`
	Sites []string `json:"sites,omitempty"`
}

type host struct{ url, token string }

type publisher interface{ publishLoop(h host) }

// hostClient trusts the daemon's own certificate (PICODE_CA_FILE) so the
// calls to PICODE_URL verify instead of failing TLS.
func hostClient() *http.Client {
	caFile := os.Getenv("PICODE_CA_FILE")
	if caFile == "" {
		return http.DefaultClient
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return http.DefaultClient
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return http.DefaultClient
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 15 * time.Second}
}

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
	var pm *passwordManager
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
		pm = &passwordManager{h: host{url: hostURL, token: extToken}, client: &http.Client{Timeout: 20 * time.Second}, device: deviceID(extToken)}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+resolvePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PiCode-Proxy-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in struct {
			Ref  string `json:"ref"`
			Kind string `json:"kind"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil || in.Ref == "" {
			answer(w, &resolveError{class: errMissing, detail: "the resolve call carried no reference"})
			return
		}
		// A site login for sign_in: username, password and the current code,
		// to the daemon only (ADR-0388 amendment of 2026-11-02).
		if in.Kind == "login" || strings.HasPrefix(in.Ref, "bwpm://") {
			if in.Kind != "login" || pm == nil {
				answer(w, &resolveError{class: errMissing, detail: "a login is only resolved for sign_in"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
			defer cancel()
			out, err := pm.login(ctx, in.Ref)
			if err != nil {
				answer(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
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

	if bv, ok := v.(*bitwardenVendor); ok && hostURL != "" && extToken != "" {
		go publishBoth(host{url: hostURL, token: extToken}, bv, pm)
	} else if pub, ok := v.(publisher); ok && hostURL != "" && extToken != "" {
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

// bitwardenVendor shells out to the pinned `bws` CLI (bws-v2.1.0, carried in
// bin/): the Secrets Manager API returns E2E-encrypted payloads, and the
// vendor's own binary does the login and decryption with the access token.
// The token rides the environment (never argv); values are fetched per
// resolve and never stored. The caches hold names and ids only.
type bitwardenVendor struct {
	h           host
	region      string
	accessToken string
	cacheAt     time.Time
	projects    map[string]string            // name -> id
	projectIDs  map[string]string            // id -> name
	secrets     map[string]map[string]string // project id -> key -> id
	mu          sync.Mutex
}

// token answers the machine account's access token: the sealed setting,
// read once and kept in memory until the publish loop sees it change.
func (o *bitwardenVendor) token(ctx context.Context) (string, error) {
	o.mu.Lock()
	if o.accessToken != "" {
		t := o.accessToken
		o.mu.Unlock()
		return t, nil
	}
	o.mu.Unlock()
	secrets, _, err := readSettings(ctx, o.h)
	if err != nil {
		return "", err
	}
	t := secrets["access_token"]
	if t == "" {
		return "", &resolveError{class: errForbidden, detail: "no access token is set; connect on the extension's page"}
	}
	o.mu.Lock()
	o.accessToken = t
	o.mu.Unlock()
	return t, nil
}

// readSettings reads the extension's settings back from the host: sealed
// secrets and plain values.
func readSettings(ctx context.Context, h host) (map[string]string, map[string]any, error) {
	if h.url == "" || h.token == "" {
		return nil, nil, &resolveError{class: errForbidden, detail: "not connected; open the extension's page"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url+"/api/ext/v1/settings", nil)
	if err != nil {
		return nil, nil, &resolveError{class: errUnavailable}
	}
	req.Header.Set("X-PiCode-Extension-Token", h.token)
	res, err := hostClient().Do(req)
	if err != nil {
		return nil, nil, &resolveError{class: errUnavailable}
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, nil, &resolveError{class: errUnavailable}
	}
	var out struct {
		Secrets map[string]string `json:"secrets"`
		Values  map[string]any    `json:"values"`
	}
	if json.NewDecoder(res.Body).Decode(&out) != nil {
		return nil, nil, &resolveError{class: errUnavailable}
	}
	return out.Secrets, out.Values, nil
}

// publishBoth keeps the tab's names current for both products: Secrets
// Manager's secrets and Password Manager's logins, whichever is connected.
func publishBoth(h host, sm *bitwardenVendor, pm *passwordManager) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		secrets, values, err := readSettings(ctx, h)
		items := []sourceItem{}
		if err == nil {
			if t := secrets["access_token"]; t != "" {
				sm.connect(t)
				if got, err := sm.items(ctx); err == nil {
					items = append(items, got...)
				} else {
					log.Printf("publish secrets: %v", err)
				}
			}
			server, _ := values["pm_server"].(string)
			clientID, _ := values["pm_client_id"].(string)
			pm.use(pmSettings{server: server, clientID: strings.TrimSpace(clientID), clientSecret: secrets["pm_client_secret"], password: secrets["pm_password"]})
			if pm.configured() {
				if got, err := pm.logins(ctx); err == nil {
					items = append(items, got...)
				} else {
					log.Printf("publish logins: %v", err)
				}
			}
			publishItems(h, items)
		}
		cancel()
		time.Sleep(30 * time.Second)
	}
}

// deviceID is a stable device identifier for this install, so the vault lists
// one device instead of one per start.
func deviceID(seed string) string {
	sum := sha256.Sum256([]byte("cognixws-bitwarden:" + seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// bws runs one pinned-CLI command with the access token in its environment.
func (o *bitwardenVendor) bws(ctx context.Context, args ...string) ([]byte, error) {
	token, err := o.token(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "./bin/bws", args...)
	cmd.Env = append(os.Environ(), "BWS_ACCESS_TOKEN="+token)
	if strings.EqualFold(o.region, "eu") {
		cmd.Env = append(cmd.Env, "BWS_API_URL=https://api.bitwarden.eu")
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := clip(strings.TrimSpace(stderr.String()))
		xe, ok := err.(*exec.ExitError)
		switch {
		case ok && xe.ExitCode() == 1 && strings.Contains(msg, "unauthorized"):
			return nil, &resolveError{class: errRevoked, detail: "the access token was refused; connect again"}
		case ok && xe.ExitCode() == 1:
			return nil, &resolveError{class: errMissing, detail: msg}
		default:
			return nil, &resolveError{class: errUnavailable, detail: msg}
		}
	}
	return out, nil
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
	raw, err := o.bws(ctx, "project", "list")
	if err != nil {
		return err
	}
	if json.Unmarshal(raw, &projects) != nil {
		return &resolveError{class: errUnavailable, detail: "the project list could not be read"}
	}
	byName, byID := map[string]string{}, map[string]string{}
	secrets := map[string]map[string]string{}
	for _, pr := range projects {
		byName[strings.ToLower(pr.Name)] = pr.ID
		byID[pr.ID] = pr.Name
		var list []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		}
		sraw, err := o.bws(ctx, "secret", "list", pr.ID)
		if err != nil {
			continue
		}
		if json.Unmarshal(sraw, &list) != nil {
			continue
		}
		byKey := map[string]string{}
		for _, sc := range list {
			byKey[strings.ToLower(sc.Key)] = sc.ID
		}
		secrets[pr.ID] = byKey
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
	raw, err := o.bws(ctx, "secret", "get", secretID)
	if err != nil {
		return "", err
	}
	var out struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &out) != nil || out.Value == "" {
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

// connect records the sealed token's latest value; the caches reset so the
// next resolve republishes under it.
func (o *bitwardenVendor) connect(token string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.accessToken == token {
		return
	}
	o.accessToken = token
	o.projects, o.projectIDs, o.secrets = nil, nil, nil
	o.cacheAt = time.Time{}
	log.Printf("connected to Bitwarden Secrets Manager")
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
	res, err := hostClient().Do(req)
	if err != nil {
		log.Printf("publish: %v", err)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("publish: %d", res.StatusCode)
		return
	}
	log.Printf("published %d names", len(items))
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

// publishLoop keeps the fixture's names on the Vaults tab the way the real
// vendor publishes them, so QA sees the populated states.
func (f *fakeVendor) publishLoop(h host) {
	for {
		publishItems(h, f.itemList)
		time.Sleep(30 * time.Second)
	}
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
