package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DarioDGR12/sandkeep/internal/api"
)

func TestLoadTLSFailClosed(t *testing.T) {
	cfg, err := api.LoadTLS(api.TLSFiles{})
	if err != nil || cfg != nil {
		t.Fatalf("empty tls must be a no-op: %v %#v", err, cfg)
	}
	if _, err := api.LoadTLS(api.TLSFiles{CertFile: "x"}); err == nil {
		t.Fatal("cert without key must fail")
	}
	if _, err := api.LoadTLS(api.TLSFiles{ClientCAFile: "x"}); err == nil {
		t.Fatal("client CA without server cert must fail")
	}
}

func TestLoadTLSAndMTLS(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := mustCA(t)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caCert)
	srvCert, srvKey := mustLeaf(t, caCert, caKey, false, []string{"localhost"})
	writePEM(t, filepath.Join(dir, "server.crt"), "CERTIFICATE", srvCert)
	writeKey(t, filepath.Join(dir, "server.key"), srvKey)

	cfg, err := api.LoadTLS(api.TLSFiles{
		CertFile:     filepath.Join(dir, "server.crt"),
		KeyFile:      filepath.Join(dir, "server.key"),
		ClientCAFile: filepath.Join(dir, "ca.crt"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("client auth=%v", cfg.ClientAuth)
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatal("min version")
	}
}

func TestCheckBindPolicyAcceptsMTLSAndJWT(t *testing.T) {
	if err := api.CheckBindPolicy("0.0.0.0:8080", api.AuthPolicy{MTLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := api.CheckBindPolicy("0.0.0.0:8080", api.AuthPolicy{JWKSURL: "https://example/jwks"}); err != nil {
		t.Fatal(err)
	}
	if err := api.CheckBindPolicy("0.0.0.0:8080", api.AuthPolicy{}); !errors.Is(err, api.ErrAnonymousPublic) {
		t.Fatalf("got %v", err)
	}
}

func mustCA(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "warden-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func mustLeaf(t *testing.T, caDER []byte, caKey *ecdsa.PrivateKey, client bool, dns []string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "warden-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
		DNSNames:     dns,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o640); err != nil {
		t.Fatal(err)
	}
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "EC PRIVATE KEY", raw)
}
