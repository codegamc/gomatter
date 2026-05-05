package gomatter

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileCertificateStore implements CertificateStore using PEM files on disk.
// This is a reference implementation intended for development and demo purposes.
// For production use, consider an implementation backed by a secure storage
// like a hardware security module (HSM) or a cloud secrets manager.
type FileCertificateStore struct {
	path string // directory where PEM files are stored
}

// NewFileCertificateStore creates a new store. If path is empty, a default directory "pem" is used.
func NewFileCertificateStore(path string) *FileCertificateStore {
	if path == "" {
		path = "pem"
	}
	return &FileCertificateStore{path: path}
}

func (s *FileCertificateStore) keyPath(name string) string {
	return filepath.Join(s.path, name+"-private.pem")
}

func (s *FileCertificateStore) certPath(name string) string {
	return filepath.Join(s.path, name+"-cert.pem")
}

func (s *FileCertificateStore) SavePrivateKey(name string, key *ecdsa.PrivateKey) error {
	// Ensure directory exists.
	if err := os.MkdirAll(s.path, 0700); err != nil {
		return fmt.Errorf("create directory %s: %w", s.path, err)
	}
	// Marshal private key.
	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	block := pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
	return os.WriteFile(s.keyPath(name), pem.EncodeToMemory(&block), 0600)
}

func (s *FileCertificateStore) LoadPrivateKey(name string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(s.keyPath(name))
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", name, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM private key")
	}
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func (s *FileCertificateStore) SaveCertificate(name string, cert *x509.Certificate) error {
	if err := os.MkdirAll(s.path, 0700); err != nil {
		return fmt.Errorf("create directory %s: %w", s.path, err)
	}
	block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return os.WriteFile(s.certPath(name), pem.EncodeToMemory(&block), 0600)
}

func (s *FileCertificateStore) LoadCertificate(name string) (*x509.Certificate, error) {
	data, err := os.ReadFile(s.certPath(name))
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", name, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return c, nil
}
