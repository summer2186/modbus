package modbus

// TlsConfig holds configuration options for TLS connections in the Modbus
// package. It allows specifying the minimum and maximum TLS versions, whether
// to skip certificate verification, an optional server name override, and the
// PEM-encoded server and client certificates and keys.
//
// ServerCert/ClientCert/ClientKey is the PEM text of the certificate/key
// (i.e. the verbatim content of the corresponding PEM file). No base64
// wrapping is applied by the caller; the strings are parsed directly with
// x509.AppendCertsFromPEM / tls.X509KeyPair.
type TlsConfig struct {
	MinVersion          string `json:"minVersion"`
	MaxVersion          string `json:"maxVersion"`
	InsecureSkipVerify  bool   `json:"insecureSkipVerify"`
	OverWriteServerName string `json:"overWriteServerName"`
	ServerCert          string `json:"serverCert"`
	ClientCert          string `json:"clientCert"`
	ClientKey           string `json:"clientKey"`
}
