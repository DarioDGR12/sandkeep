package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSFiles is the on-disk material for HTTPS and optional mTLS.
type TLSFiles struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

// LoadTLS builds a tls.Config. ClientCAFile enables
// RequireAndVerifyClientCert (mTLS). Partial configs fail closed.
func LoadTLS(f TLSFiles) (*tls.Config, error) {
	if f.CertFile == "" && f.KeyFile == "" && f.ClientCAFile == "" {
		return nil, nil
	}
	if f.CertFile == "" || f.KeyFile == "" {
		return nil, fmt.Errorf("tls: both WARDEN_TLS_CERT and WARDEN_TLS_KEY are required")
	}
	if f.ClientCAFile != "" && (f.CertFile == "" || f.KeyFile == "") {
		return nil, fmt.Errorf("tls: WARDEN_TLS_CLIENT_CA requires a server certificate")
	}
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: load server cert: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if f.ClientCAFile != "" {
		pem, err := os.ReadFile(f.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls: read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls: client CA file has no certificates")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
