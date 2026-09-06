// Copyright 2014 Quoc-Viet Nguyen. All rights reserved.
// This software may be modified and distributed under the terms
// of the BSD license. See the LICENSE file for details.

package modbus

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// newTLSTestCerts generates a self-signed CA/server certificate and a client
// certificate signed by it, returning a server-side tls.Config (that requires
// and verifies client certs) plus the PEM strings a client needs.
//
// The server cert carries DNS name "testserver"; clients pair it with
// OverWriteServerName: "testserver" so verification succeeds without
// InsecureSkipVerify, covering the ServerName override path.
func newTLSTestCerts(t *testing.T) (serverTLS *tls.Config, serverCertPEM, clientCertPEM, clientKeyPEM string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "modbus-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"testserver"},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	serverCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "modbus-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	clientCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}))
	clientKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}))

	serverCert, err := tls.X509KeyPair([]byte(serverCertPEM), caKeyPEM)
	if err != nil {
		t.Fatalf("server X509KeyPair: %v", err)
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCert)

	serverTLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	return
}

// startTLSEchoServer starts a TLS echo server (io.Copy loopback) on a random
// local port. The returned listener is already accepting; the goroutine stops
// when the listener is closed.
func startTLSEchoServer(t *testing.T, serverTLS *tls.Config) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln
}

// TestTLSConfigConversion checks the TlsConfig -> *tls.Config mapping for every
// field, including error paths for bad version strings and malformed PEM.
func TestTLSConfigConversion(t *testing.T) {
	_, serverCertPEM, clientCertPEM, clientKeyPEM := newTLSTestCerts(t)

	cfg, err := newTLSConfig(&TlsConfig{
		MinVersion:          "TLS1.2",
		MaxVersion:          "TLS1.3",
		InsecureSkipVerify:  true,
		OverWriteServerName: "server.example",
		ServerCert:          serverCertPEM,
		ClientCert:          clientCertPEM,
		ClientKey:           clientKeyPEM,
	})
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
	}
	if cfg.InsecureSkipVerify != true {
		t.Fatalf("InsecureSkipVerify: expected true, got %v", cfg.InsecureSkipVerify)
	}
	if cfg.ServerName != "server.example" {
		t.Fatalf("ServerName: expected server.example, got %v", cfg.ServerName)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion: expected %x, got %x", tls.VersionTLS12, cfg.MinVersion)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("MaxVersion: expected %x, got %x", tls.VersionTLS13, cfg.MaxVersion)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs: expected non-nil")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates: expected 1, got %d", len(cfg.Certificates))
	}

	// Lenient version parsing variants.
	for _, s := range []string{"tls 1.2", "1.2", "TLS12"} {
		if _, err := parseTLSVersion(s); err != nil {
			t.Fatalf("parseTLSVersion(%q): %v", s, err)
		}
	}
	if _, err := parseTLSVersion("bogus"); err == nil {
		t.Fatal("parseTLSVersion: expected error for bogus version")
	}

	// Empty Min/Max must be left unset (no error).
	cfg2, err := newTLSConfig(&TlsConfig{InsecureSkipVerify: true})
	if err != nil || cfg2.MinVersion != 0 || cfg2.MaxVersion != 0 {
		t.Fatalf("empty versions: cfg=%+v err=%v", cfg2, err)
	}

	// Invalid MinVersion surfaces an error.
	if _, err := newTLSConfig(&TlsConfig{MinVersion: "bogus"}); err == nil {
		t.Fatal("expected error for invalid MinVersion")
	}

	// Malformed server cert PEM surfaces an error.
	if _, err := newTLSConfig(&TlsConfig{ServerCert: "not a PEM"}); err == nil {
		t.Fatal("expected error for invalid ServerCert PEM")
	}

	// Malformed client key pair surfaces an error.
	if _, err := newTLSConfig(&TlsConfig{ClientCert: clientCertPEM, ClientKey: "bad"}); err == nil {
		t.Fatal("expected error for invalid ClientKey PEM")
	}
}

// TestTCPTlsTransporter exercises tcpTransporter.Send over a mutual-TLS echo
// server, covering ServerCert/ClientCert/ClientKey/OverWriteServerName, then
// asserts the idle timer closes the connection.
func TestTCPTlsTransporter(t *testing.T) {
	serverTLS, serverCertPEM, clientCertPEM, clientKeyPEM := newTLSTestCerts(t)
	ln := startTLSEchoServer(t, serverTLS)
	defer ln.Close()

	client := &tcpTransporter{
		Address:     ln.Addr().String(),
		Timeout:     1 * time.Second,
		IdleTimeout: 100 * time.Millisecond,
		TLS: &TlsConfig{
			ServerCert:          serverCertPEM,
			ClientCert:          clientCertPEM,
			ClientKey:           clientKeyPEM,
			OverWriteServerName: "testserver",
		},
	}
	req := []byte{0, 1, 0, 2, 0, 2, 1, 2}
	rsp, err := client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req, rsp) {
		t.Fatalf("unexpected response: %x", rsp)
	}
	time.Sleep(150 * time.Millisecond)
	if client.conn != nil {
		t.Fatalf("connection is not closed: %+v", client.conn)
	}
}

// TestTCPTlsTransporterInsecure covers the InsecureSkipVerify path: connect to
// a self-signed server without trusting its cert.
func TestTCPTlsTransporterInsecure(t *testing.T) {
	serverTLS, _, _, _ := newTLSTestCerts(t)
	// Relax mutual TLS so an insecure client (no client cert) can connect.
	serverTLS.ClientAuth = tls.NoClientCert
	ln := startTLSEchoServer(t, serverTLS)
	defer ln.Close()

	client := &tcpTransporter{
		Address:     ln.Addr().String(),
		Timeout:     1 * time.Second,
		IdleTimeout: 100 * time.Millisecond,
		TLS: &TlsConfig{
			InsecureSkipVerify: true,
		},
	}
	req := []byte{0, 1, 0, 2, 0, 2, 1, 2}
	rsp, err := client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req, rsp) {
		t.Fatalf("unexpected response: %x", rsp)
	}
}

// TestRTUTCPTlsTransporter mirrors TestRTUTCPTransporter but over TLS, using a
// WriteSingleRegister RTU frame whose request/response lengths match so the
// echo server returns exactly what calculateResponseLength predicts.
func TestRTUTCPTlsTransporter(t *testing.T) {
	serverTLS, serverCertPEM, clientCertPEM, clientKeyPEM := newTLSTestCerts(t)
	ln := startTLSEchoServer(t, serverTLS)
	defer ln.Close()

	client := &rtuTCPTransporter{
		tcpTransporter: tcpTransporter{
			Address:     ln.Addr().String(),
			Timeout:     1 * time.Second,
			IdleTimeout: 100 * time.Millisecond,
			TLS: &TlsConfig{
				ServerCert:          serverCertPEM,
				ClientCert:          clientCertPEM,
				ClientKey:           clientKeyPEM,
				OverWriteServerName: "testserver",
			},
		},
	}

	packager := rtuPackager{SlaveId: 0x01}
	pdu := &ProtocolDataUnit{
		FunctionCode: FuncCodeWriteSingleRegister,
		Data:         dataBlock(0x0001, 0x0003),
	}
	req, err := packager.Encode(pdu)
	if err != nil {
		t.Fatal(err)
	}
	rsp, err := client.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(req, rsp) {
		t.Fatalf("unexpected response: % x", rsp)
	}
	time.Sleep(150 * time.Millisecond)
	if client.conn != nil {
		t.Fatalf("connection is not closed: %+v", client.conn)
	}
}

// TestTlsClient guards the convenience constructor and its wiring into the
// Client interface.
func TestTlsClient(t *testing.T) {
	_, serverCertPEM, clientCertPEM, clientKeyPEM := newTLSTestCerts(t)
	cl := TlsClient("127.0.0.1:0", &TlsConfig{
		ServerCert:          serverCertPEM,
		ClientCert:          clientCertPEM,
		ClientKey:           clientKeyPEM,
		OverWriteServerName: "testserver",
	})
	if cl == nil {
		t.Fatal("expected non-nil client")
	}
}

// TestRTUTlsClient guards the RTU TLS convenience constructor.
func TestRTUTlsClient(t *testing.T) {
	_, serverCertPEM, clientCertPEM, clientKeyPEM := newTLSTestCerts(t)
	cl := RTUTlsClient("127.0.0.1:0", &TlsConfig{
		ServerCert:          serverCertPEM,
		ClientCert:          clientCertPEM,
		ClientKey:           clientKeyPEM,
		OverWriteServerName: "testserver",
	})
	if cl == nil {
		t.Fatal("expected non-nil client")
	}
}
