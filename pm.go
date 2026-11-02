package main

// Bitwarden Password Manager logins for the browser tool's sign_in (ADR-0388
// amendment of 2026-11-02). The vault's API answers end-to-end encrypted
// items, so this file decrypts them the way a Bitwarden client does: the
// master key from the master password and the account's KDF, the user key it
// protects, then each item's fields. Personal-vault logins only; an
// organization's items need its key, which this does not read yet.
//
// Sign-in is the personal API key (client_credentials), so no new-device
// email code is asked; the master password unlocks. Both are sealed settings
// of the extension. Decrypted values live in memory for one resolve.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// pmSettings are the extension's Password Manager settings.
type pmSettings struct {
	server, clientID, clientSecret, password string
}

func (s pmSettings) configured() bool {
	return s.clientID != "" && s.clientSecret != "" && s.password != ""
}

// endpoints answers the identity and API addresses: the cloud's own hosts for
// bitwarden.com and bitwarden.eu, else a self-hosted server's paths.
func (s pmSettings) endpoints() (identity, api string) {
	server := strings.TrimRight(strings.TrimSpace(s.server), "/")
	switch strings.ToLower(server) {
	case "", "https://vault.bitwarden.com", "https://bitwarden.com":
		return "https://identity.bitwarden.com", "https://api.bitwarden.com"
	case "https://vault.bitwarden.eu", "https://bitwarden.eu":
		return "https://identity.bitwarden.eu", "https://api.bitwarden.eu"
	}
	return server + "/identity", server + "/api"
}

type passwordManager struct {
	h      host
	client *http.Client
	device string

	mu       sync.Mutex
	settings pmSettings
	userKey  []byte // 64 bytes: AES key, then MAC key
	token    string
	expires  time.Time
	ciphers  []pmCipher
	syncedAt time.Time
}

type pmCipher struct {
	ID             string  `json:"id"`
	Type           int     `json:"type"`
	Name           string  `json:"name"`
	Key            *string `json:"key"`
	OrganizationID *string `json:"organizationId"`
	DeletedDate    *string `json:"deletedDate"`
	Login          *struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
		Totp     *string `json:"totp"`
		Uris     []struct {
			URI *string `json:"uri"`
		} `json:"uris"`
	} `json:"login"`
}

var errNotConfigured = &resolveError{class: errForbidden, detail: "Password Manager is not connected; set the API key and master password on the extension's page"}

// use records the latest sealed settings; a change forgets the session.
func (p *passwordManager) use(s pmSettings) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.settings == s {
		return
	}
	p.settings = s
	p.userKey, p.token, p.ciphers = nil, "", nil
	p.expires, p.syncedAt = time.Time{}, time.Time{}
}

func (p *passwordManager) configured() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.settings.configured()
}

// session signs in with the API key and unlocks the user key, once per token.
func (p *passwordManager) session(ctx context.Context) (string, []byte, error) {
	p.mu.Lock()
	s, token, key, exp := p.settings, p.token, p.userKey, p.expires
	p.mu.Unlock()
	if !s.configured() {
		return "", nil, errNotConfigured
	}
	if token != "" && key != nil && time.Until(exp) > time.Minute {
		return token, key, nil
	}
	identity, _ := s.endpoints()
	form := url.Values{
		"grant_type": {"client_credentials"}, "scope": {"api"},
		"client_id": {s.clientID}, "client_secret": {s.clientSecret},
		"deviceType": {"21"}, "deviceIdentifier": {p.device}, "deviceName": {"COGNIX[WS]"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, identity+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, &resolveError{class: errUnavailable}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Device-Type", "21")
	res, err := p.client.Do(req)
	if err != nil {
		return "", nil, &resolveError{class: errUnavailable, detail: "the vault did not answer"}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusUnauthorized {
		return "", nil, &resolveError{class: errForbidden, detail: "the vault refused the API key; check it on the extension's page"}
	}
	if res.StatusCode != http.StatusOK {
		return "", nil, &resolveError{class: errUnavailable, detail: "the vault answered " + res.Status}
	}
	var out struct {
		AccessToken    string `json:"access_token"`
		ExpiresIn      int    `json:"expires_in"`
		Key            string `json:"Key"`
		Kdf            int    `json:"Kdf"`
		KdfIterations  int    `json:"KdfIterations"`
		KdfMemory      *int   `json:"KdfMemory"`
		KdfParallelism *int   `json:"KdfParallelism"`
	}
	if json.Unmarshal(body, &out) != nil || out.AccessToken == "" || out.Key == "" {
		return "", nil, &resolveError{class: errUnavailable, detail: "the vault's sign-in answer could not be read"}
	}
	email, err := p.email(ctx, out.AccessToken)
	if err != nil {
		return "", nil, err
	}
	master, err := masterKey(s.password, email, out.Kdf, out.KdfIterations, out.KdfMemory, out.KdfParallelism)
	if err != nil {
		return "", nil, err
	}
	enc, mac := stretch(master)
	userKey, err := decryptEncString(out.Key, enc, mac)
	if err != nil || len(userKey) != 64 {
		return "", nil, &resolveError{class: errForbidden, detail: "the master password does not unlock this vault"}
	}
	p.mu.Lock()
	p.token, p.userKey = out.AccessToken, userKey
	p.expires = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	p.mu.Unlock()
	return out.AccessToken, userKey, nil
}

func (p *passwordManager) get(ctx context.Context, token, path string, into any) error {
	_, api := p.settingsNow().endpoints()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+path, nil)
	if err != nil {
		return &resolveError{class: errUnavailable}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := p.client.Do(req)
	if err != nil {
		return &resolveError{class: errUnavailable, detail: "the vault did not answer"}
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		p.mu.Lock()
		p.token = ""
		p.mu.Unlock()
		return &resolveError{class: errUnavailable, detail: "the vault session ended; try again"}
	}
	if res.StatusCode != http.StatusOK {
		return &resolveError{class: errUnavailable, detail: "the vault answered " + res.Status}
	}
	return json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(into)
}

func (p *passwordManager) settingsNow() pmSettings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.settings
}

func (p *passwordManager) email(ctx context.Context, token string) (string, error) {
	var profile struct {
		Email string `json:"email"`
	}
	if err := p.get(ctx, token, "/accounts/profile", &profile); err != nil {
		return "", err
	}
	if profile.Email == "" {
		return "", &resolveError{class: errUnavailable, detail: "the vault answered no account"}
	}
	return profile.Email, nil
}

// sync answers the vault's items, read at most once a minute.
func (p *passwordManager) sync(ctx context.Context) ([]pmCipher, []byte, error) {
	token, key, err := p.session(ctx)
	if err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	if p.ciphers != nil && time.Since(p.syncedAt) < time.Minute {
		c := p.ciphers
		p.mu.Unlock()
		return c, key, nil
	}
	p.mu.Unlock()
	var out struct {
		Ciphers []pmCipher `json:"ciphers"`
	}
	if err := p.get(ctx, token, "/sync?excludeDomains=true", &out); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	p.ciphers, p.syncedAt = out.Ciphers, time.Now()
	p.mu.Unlock()
	return out.Ciphers, key, nil
}

// itemKey is the key a cipher's fields are encrypted with: its own when it
// carries one, else the user key.
func itemKey(c pmCipher, user []byte) ([]byte, error) {
	if c.Key == nil || *c.Key == "" {
		return user, nil
	}
	k, err := decryptEncString(*c.Key, user[:32], user[32:])
	if err != nil || len(k) != 64 {
		return nil, errors.New("the item's key could not be read")
	}
	return k, nil
}

func field(v *string, key []byte) string {
	if v == nil || *v == "" {
		return ""
	}
	out, err := decryptEncString(*v, key[:32], key[32:])
	if err != nil {
		return ""
	}
	return string(out)
}

// usable is a personal, not deleted login.
func usable(c pmCipher) bool {
	return c.Type == 1 && c.Login != nil && c.DeletedDate == nil && (c.OrganizationID == nil || *c.OrganizationID == "")
}

// logins publishes the personal logins as names and sites, never a value.
func (p *passwordManager) logins(ctx context.Context) ([]sourceItem, error) {
	ciphers, user, err := p.sync(ctx)
	if err != nil {
		return nil, err
	}
	out := []sourceItem{}
	for _, c := range ciphers {
		if !usable(c) {
			continue
		}
		key, err := itemKey(c, user)
		if err != nil {
			continue
		}
		sites := []string{}
		seen := map[string]bool{}
		for _, u := range c.Login.Uris {
			if host := siteOf(field(u.URI, key)); host != "" && !seen[host] && len(sites) < 16 {
				seen[host] = true
				sites = append(sites, host)
			}
		}
		if len(sites) == 0 {
			continue
		}
		name := field(&c.Name, key)
		if name == "" {
			name = sites[0]
		}
		out = append(out, sourceItem{Ref: "bwpm://" + c.ID, Label: name, Vault: "Personal", Kind: "login", Sites: sites})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

// login answers one login's username, password and current code.
func (p *passwordManager) login(ctx context.Context, ref string) (map[string]string, error) {
	id, ok := strings.CutPrefix(ref, "bwpm://")
	if !ok || id == "" {
		return nil, &resolveError{class: errMissing, detail: "a login reads bwpm://<item id>"}
	}
	ciphers, user, err := p.sync(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range ciphers {
		if c.ID != id {
			continue
		}
		if !usable(c) {
			return nil, &resolveError{class: errMissing, detail: "that item is not a personal login"}
		}
		key, err := itemKey(c, user)
		if err != nil {
			return nil, &resolveError{class: errUnavailable, detail: err.Error()}
		}
		out := map[string]string{"username": field(c.Login.Username, key), "password": field(c.Login.Password, key)}
		if secret := field(c.Login.Totp, key); secret != "" {
			if code, err := totpNow(secret, time.Now()); err == nil {
				out["totp"] = code
			}
		}
		if out["password"] == "" {
			return nil, &resolveError{class: errMissing, detail: "that login has no password"}
		}
		return out, nil
	}
	return nil, &resolveError{class: errMissing, detail: "that login is no longer in the vault"}
}

// siteOf is a URI's host when it is a web address.
func siteOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.Contains(host, ":") {
		return ""
	}
	return host
}

// masterKey derives the master key: PBKDF2-SHA256 (kdf 0) salted with the
// email, or Argon2id (kdf 1) salted with the email's SHA-256.
func masterKey(password, email string, kdf, iterations int, memory, parallelism *int) ([]byte, error) {
	salt := []byte(strings.ToLower(strings.TrimSpace(email)))
	switch kdf {
	case 0:
		if iterations < 5000 {
			return nil, &resolveError{class: errUnavailable, detail: "the vault's key settings are not supported"}
		}
		return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New), nil
	case 1:
		if memory == nil || parallelism == nil || iterations < 1 {
			return nil, &resolveError{class: errUnavailable, detail: "the vault's key settings are not supported"}
		}
		s := sha256.Sum256(salt)
		return argon2.IDKey([]byte(password), s[:], uint32(iterations), uint32(*memory)*1024, uint8(*parallelism), 32), nil
	}
	return nil, &resolveError{class: errUnavailable, detail: "the vault's key settings are not supported"}
}

// stretch expands the master key into its encryption and MAC keys
// (HKDF-Expand with SHA-256, one block each).
func stretch(master []byte) (enc, mac []byte) {
	expand := func(info string) []byte {
		h := hmac.New(sha256.New, master)
		h.Write([]byte(info))
		h.Write([]byte{1})
		return h.Sum(nil)
	}
	return expand("enc"), expand("mac")
}

// decryptEncString opens a type-2 EncString ("2.iv|data|mac"): the MAC is
// checked before anything is decrypted.
func decryptEncString(s string, enc, mac []byte) ([]byte, error) {
	kind, rest, ok := strings.Cut(s, ".")
	if !ok || kind != "2" {
		return nil, errors.New("unsupported encryption")
	}
	parts := strings.Split(rest, "|")
	if len(parts) != 3 {
		return nil, errors.New("malformed encryption")
	}
	iv, err1 := base64.StdEncoding.DecodeString(parts[0])
	data, err2 := base64.StdEncoding.DecodeString(parts[1])
	tag, err3 := base64.StdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != aes.BlockSize || len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("malformed encryption")
	}
	h := hmac.New(sha256.New, mac)
	h.Write(iv)
	h.Write(data)
	if !hmac.Equal(h.Sum(nil), tag) {
		return nil, errors.New("the key does not open this value")
	}
	block, err := aes.NewCipher(enc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(out) {
		return nil, errors.New("malformed padding")
	}
	return out[:len(out)-pad], nil
}

// totpNow is the current code for a login's TOTP field: a base32 secret or an
// otpauth:// URI (digits, period and algorithm honoured).
func totpNow(secret string, now time.Time) (string, error) {
	digits, period := 6, int64(30)
	var alg func() hash.Hash = sha1.New
	if strings.HasPrefix(strings.ToLower(secret), "otpauth://") {
		u, err := url.Parse(secret)
		if err != nil {
			return "", err
		}
		q := u.Query()
		secret = q.Get("secret")
		if d, err := strconv.Atoi(q.Get("digits")); err == nil && d >= 6 && d <= 8 {
			digits = d
		}
		if p, err := strconv.ParseInt(q.Get("period"), 10, 64); err == nil && p > 0 && p <= 300 {
			period = p
		}
		switch strings.ToUpper(q.Get("algorithm")) {
		case "SHA256":
			alg = sha256.New
		case "SHA512":
			alg = sha512.New
		}
	}
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil || len(key) == 0 {
		return "", fmt.Errorf("the TOTP secret is not base32")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/period))
	h := hmac.New(alg, key)
	h.Write(counter[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod), nil
}
