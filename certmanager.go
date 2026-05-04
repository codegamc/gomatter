package gomatter

import (
	"crypto/ecdsa"
	"crypto/x509"
)

// matter certificate manager interface
// all generated certificates must be compatible with matter
//   - this means that after they are reencoded to matter format and back their signature must match
type CertificateManager interface {
	GetCaPublicKey() ecdsa.PublicKey
	GetCaCertificate() *x509.Certificate

	// ProvisionNodeIdentity creates keys and certificate for node with specific id
	// it must be possible to later retrieve node keys using GetPrivkey and certificate using GetCertificate
	ProvisionNodeIdentity(nodeId uint64) error

	// retrieve certificate of specified node (previously created by ProvisionNodeIdentity)
	GetCertificate(nodeId uint64) (*x509.Certificate, error)

	// retrieve key of specified node (previously created by ProvisionNodeIdentity)
	GetPrivkey(nodeId uint64) (*ecdsa.PrivateKey, error)

	// create and sign certificate using local CA keys
	SignCertificate(userPublicKey *ecdsa.PublicKey, nodeId uint64) (*x509.Certificate, error)
}
