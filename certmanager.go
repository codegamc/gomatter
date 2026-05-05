// Package gomatter provides certificate management.
package gomatter

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// CertificateManager defines certificate management operations.
// all generated certificates must be compatible with matter
//   - this means that after they are reencoded to matter format and back their signature must match
type CertificateManager interface {
	// GetCACertificate retrieves CA certificate
	GetCACertificate() (*x509.Certificate, error)

	// GetCAPublicKey retrieves CA public key
	GetCAPublicKey() (ecdsa.PublicKey, error)

	// GetNodeCertificate retrieves certificate of specified node
	GetNodeCertificate(nodeId uint64) (*x509.Certificate, error)

	// GetNodePrivateKey retrieves key of specified node
	GetNodePrivateKey(nodeId uint64) (*ecdsa.PrivateKey, error)

	// SignCertificate creates and sign certificate using local CA keys
	SignCertificate(pubKey *ecdsa.PublicKey, nodeId uint64) (*x509.Certificate, error)
}
