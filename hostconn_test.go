package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// hostConnServer stands in for the daemon over TLS with a CA of its own, the
// way PICODE_CA_FILE points at the daemon's certificate, and counts every
// TCP connection it accepts.
func hostConnServer(t *testing.T) (srv *httptest.Server, conns *int32, caFile string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "picode test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ext/v1/settings", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"secrets": map[string]string{}, "values": map[string]any{}})
	})
	mux.HandleFunc("POST /api/ext/v1/vaults/items", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	var count int32
	srv = httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER, caDER}, PrivateKey: srvKey}}, MinVersion: tls.VersionTLS12}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&count, 1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &count, caFile
}

// TestHostClientShared pins one client for the life of the process: every
// hostClient() call answers the same instance, not a fresh transport per
// call (which left an idle loopback connection behind every publish round).
func TestHostClientShared(t *testing.T) {
	_, _, caFile := hostConnServer(t)
	t.Setenv("PICODE_CA_FILE", caFile)
	first := hostClient()
	for i := 0; i < 10; i++ {
		if again := hostClient(); again != first {
			t.Fatalf("hostClient() call %d returned a new client %p instead of the shared one %p", i+1, again, first)
		}
	}
}

// TestHostConnectionsBounded counts the connections the daemon side sees
// over many calls, like 30 minutes of publish rounds: they must stay
// bounded, not one per call.
func TestHostConnectionsBounded(t *testing.T) {
	srv, conns, caFile := hostConnServer(t)
	t.Setenv("PICODE_CA_FILE", caFile)

	h := host{url: srv.URL, token: "test-token"}
	const rounds = 60
	for i := 0; i < rounds; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, _, err := readSettings(ctx, h); err != nil {
			t.Fatalf("readSettings call %d: %v", i+1, err)
		}
		cancel()
		publishItems(h, []sourceItem{{Ref: "bws://QA/api-key", Label: "api-key", Vault: "QA"}})
	}
	time.Sleep(100 * time.Millisecond)

	got := atomic.LoadInt32(conns)
	t.Logf("host connections opened for %d calls: %d", rounds*2, got)
	const limit = 5
	if got > limit {
		t.Fatalf("%d calls opened %d connections (limit %d): one idle connection left behind per call", rounds*2, got, limit)
	}
}
