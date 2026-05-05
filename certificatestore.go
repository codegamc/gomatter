// Package gomatter provides certificate management.
package gomatter

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// CertificateStore defines storage operations for keys and certificates.
type CertificateStore interface {
	SavePrivateKey(name string, key *ecdsa.PrivateKey) error
	LoadPrivateKey(name string) (*ecdsa.PrivateKey, error)
	SaveCertificate(name string, cert *x509.Certificate) error
	LoadCertificate(name string) (*x509.Certificate, error)
}
