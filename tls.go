// Copyright 2014 Quoc-Viet Nguyen. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

package modbus

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

// newTLSConfig converts a TlsConfig into a *tls.Config suitable for dialing a
// TLS-wrapped Modbus server. It is called lazily by tcpTransporter.connect
// when a TLS connection is requested.
//
// Empty MinVersion/MaxVersion are left unset so the standard library defaults
// apply. Empty ServerCert/ClientCert leave the corresponding tls.Config field
// nil. This keeps the common "InsecureSkipVerify only" case trivial.
func newTLSConfig(c *TlsConfig) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
	}
	if c.OverWriteServerName != "" {
		cfg.ServerName = c.OverWriteServerName
	}
	if c.MinVersion != "" {
		v, err := parseTLSVersion(c.MinVersion)
		if err != nil {
			return nil, err
		}
		cfg.MinVersion = v
	}
	if c.MaxVersion != "" {
		v, err := parseTLSVersion(c.MaxVersion)
		if err != nil {
			return nil, err
		}
		cfg.MaxVersion = v
	}
	if c.ServerCert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.ServerCert)) {
			return nil, errors.New("modbus: failed to parse server certificate PEM")
		}
		cfg.RootCAs = pool
	}
	// X509KeyPair returns an error if either operand is empty, so only build
	// a client certificate when both sides are supplied.
	if c.ClientCert != "" && c.ClientKey != "" {
		cert, err := tls.X509KeyPair([]byte(c.ClientCert), []byte(c.ClientKey))
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// parseTLSVersion maps a human-friendly TLS version string to the uint16
// constant used by crypto/tls. It accepts the forms "TLS1.2", "TLS 1.2",
// "1.2" and "tls12" (case-insensitive, whitespace ignored). An empty string
// is handled by the caller, not here.
func parseTLSVersion(s string) (uint16, error) {
	// Normalize: lowercase and drop all spaces.
	norm := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	switch norm {
	case "tls1.0", "1.0", "tls10":
		return tls.VersionTLS10, nil
	case "tls1.1", "1.1", "tls11":
		return tls.VersionTLS11, nil
	case "tls1.2", "1.2", "tls12":
		return tls.VersionTLS12, nil
	case "tls1.3", "1.3", "tls13":
		return tls.VersionTLS13, nil
	default:
		return 0, errors.New("modbus: unsupported TLS version: " + s)
	}
}
