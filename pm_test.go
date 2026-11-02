package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// seal is a Bitwarden client's encryption, for the fixtures.
func seal(t *testing.T, plain, enc, mac []byte) string {
	t.Helper()
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	data := append(append([]byte{}, plain...), []byte(strings.Repeat(string(rune(pad)), pad))...)
	block, _ := aes.NewCipher(enc)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	h := hmac.New(sha256.New, mac)
	h.Write(iv)
	h.Write(data)
	b := base64.StdEncoding.EncodeToString
	return "2." + b(iv) + "|" + b(data) + "|" + b(h.Sum(nil))
}

// fakeVault answers a vault's identity, profile and sync the way Vaultwarden
// does, with one personal login, one deleted, one organization item, one
// login with its own item key, and a note.
func fakeVault(t *testing.T, password string) *httptest.Server {
	t.Helper()
	email := "QA@vault.test"
	master := pbkdf2.Key([]byte(password), []byte(strings.ToLower(email)), 600000, 32, sha256.New)
	enc, mac := stretch(master)
	user := make([]byte, 64)
	_, _ = rand.Read(user)
	ue, um := user[:32], user[32:]
	s := func(v string) *string { x := seal(t, []byte(v), ue, um); return &x }
	itemKey := make([]byte, 64)
	_, _ = rand.Read(itemKey)
	ik := func(v string) *string { x := seal(t, []byte(v), itemKey[:32], itemKey[32:]); return &x }
	wrapped := seal(t, itemKey, ue, um)
	totp := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	deleted, org := "2026-01-01T00:00:00Z", "org-1"
	login := func(name, user, pass, uri string, f func(string) *string) map[string]any {
		return map[string]any{"name": *f(name), "login": map[string]any{"username": f(user), "password": f(pass), "totp": f(totp), "uris": []map[string]any{{"uri": f(uri)}, {"uri": f("androidapp://x")}}}}
	}
	ciphers := []map[string]any{}
	add := func(id string, typ int, body map[string]any, extra map[string]any) {
		c := map[string]any{"id": id, "type": typ}
		for k, v := range body {
			c[k] = v
		}
		for k, v := range extra {
			c[k] = v
		}
		ciphers = append(ciphers, c)
	}
	add("c1", 1, login("QA login", "qa-user@example.test", "filled-by-vault-7391", "http://localhost:8223/login", s), nil)
	add("c2", 1, login("Gone", "u", "p", "https://gone.test", s), map[string]any{"deletedDate": deleted})
	add("c3", 1, login("Org", "u", "p", "https://org.test", s), map[string]any{"organizationId": org})
	add("c4", 1, login("Own key", "k-user", "k-pass", "github.com", ik), map[string]any{"key": wrapped})
	add("c5", 2, map[string]any{"name": *s("A note")}, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_secret") != "sec" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600, "Key": seal(t, user, enc, mac), "Kdf": 0, "KdfIterations": 600000})
	})
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/accounts/profile", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			_ = json.NewEncoder(w).Encode(map[string]any{"email": email})
		}
	})
	mux.HandleFunc("GET /api/sync", func(w http.ResponseWriter, r *http.Request) {
		if auth(w, r) {
			_ = json.NewEncoder(w).Encode(map[string]any{"ciphers": ciphers})
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newPM(srv *httptest.Server, password string) *passwordManager {
	p := &passwordManager{client: srv.Client(), device: deviceID("t")}
	p.use(pmSettings{server: srv.URL, clientID: "user.x", clientSecret: "sec", password: password})
	return p
}

func TestPasswordManagerLoginsAndResolve(t *testing.T) {
	srv := fakeVault(t, "correct horse")
	p := newPM(srv, "correct horse")
	ctx := context.Background()
	items, err := p.logins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Label != "Own key" || items[1].Label != "QA login" {
		t.Fatalf("published: %+v (deleted, organization and note items must not be)", items)
	}
	raw, _ := json.Marshal(items)
	for _, v := range []string{"filled-by-vault", "qa-user@", "k-pass"} {
		if strings.Contains(string(raw), v) {
			t.Fatalf("the published names carry %q", v)
		}
	}
	if items[1].Kind != "login" || len(items[1].Sites) != 1 || items[1].Sites[0] != "localhost" {
		t.Fatalf("sites: %+v", items[1])
	}
	got, err := p.login(ctx, "bwpm://c1")
	if err != nil || got["username"] != "qa-user@example.test" || got["password"] != "filled-by-vault-7391" || len(got["totp"]) != 6 {
		t.Fatalf("login: %v %v", got, err)
	}
	if got, err := p.login(ctx, "bwpm://c4"); err != nil || got["password"] != "k-pass" {
		t.Fatalf("an item with its own key: %v %v", got, err)
	}
	for _, ref := range []string{"bwpm://c2", "bwpm://c3", "bwpm://c5", "bwpm://none", "c1"} {
		if _, err := p.login(ctx, ref); err == nil {
			t.Errorf("%s resolved", ref)
		}
	}
}

func TestPasswordManagerWrongPasswordOrKey(t *testing.T) {
	srv := fakeVault(t, "correct horse")
	if _, err := newPM(srv, "wrong").logins(context.Background()); err == nil || !strings.Contains(err.Error(), "master password") {
		t.Fatalf("wrong master password: %v", err)
	}
	p := newPM(srv, "correct horse")
	p.use(pmSettings{server: srv.URL, clientID: "user.x", clientSecret: "bad", password: "correct horse"})
	if _, err := p.logins(context.Background()); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("wrong API key: %v", err)
	}
	if (&passwordManager{}).configured() {
		t.Fatal("an empty setting is configured")
	}
}

// RFC 6238 appendix B, SHA-1, eight digits.
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	uri := "otpauth://totp/x?secret=" + strings.TrimRight(secret, "=") + "&digits=8"
	for at, want := range map[int64]string{59: "94287082", 1111111109: "07081804", 1234567890: "89005924"} {
		got, err := totpNow(uri, time.Unix(at, 0))
		if err != nil || got != want {
			t.Errorf("%d: %s %v, want %s", at, got, err, want)
		}
	}
	if got, err := totpNow(strings.ToLower(secret), time.Unix(59, 0)); err != nil || got != "287082" {
		t.Errorf("a bare secret: %s %v", got, err)
	}
}

func TestEndpoints(t *testing.T) {
	for server, want := range map[string]string{"": "https://identity.bitwarden.com", "https://vault.bitwarden.eu": "https://identity.bitwarden.eu", "https://vw.example.test/": "https://vw.example.test/identity"} {
		if got, _ := (pmSettings{server: server}).endpoints(); got != want {
			t.Errorf("%q: %s", server, got)
		}
	}
}
