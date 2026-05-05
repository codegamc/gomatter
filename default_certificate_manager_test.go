package gomatter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type memoryCertificateStore struct {
	keys  map[string]*ecdsa.PrivateKey
	certs map[string]*x509.Certificate
}

func newMemoryStore() *memoryCertificateStore {
	return &memoryCertificateStore{
		keys:  make(map[string]*ecdsa.PrivateKey),
		certs: make(map[string]*x509.Certificate),
	}
}

func (s *memoryCertificateStore) SavePrivateKey(name string, key *ecdsa.PrivateKey) error {
	s.keys[name] = key
	return nil
}

func (s *memoryCertificateStore) LoadPrivateKey(name string) (*ecdsa.PrivateKey, error) {
	k, ok := s.keys[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return k, nil
}

func (s *memoryCertificateStore) SaveCertificate(name string, cert *x509.Certificate) error {
	s.certs[name] = cert
	return nil
}

func (s *memoryCertificateStore) LoadCertificate(name string) (*x509.Certificate, error) {
	c, ok := s.certs[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return c, nil
}

func TestDefaultCertificateManager_InMemory_FullLifecycle(t *testing.T) {
	fabricID := uint64(0x12345678)
	rcacID := uint64(0xABCDEF)
	nodeID := uint64(0xDEADBEEF)

	store := newMemoryStore()
	cm := NewDefaultCertificateManager(fabricID, store)

	// 1. Initialize Root CA
	if err := cm.InitializeRootCA(rcacID); err != nil {
		t.Fatalf("InitializeRootCA failed: %v", err)
	}

	caCert, err := cm.GetCACertificate()
	if err != nil {
		t.Fatalf("GetCACertificate failed: %v", err)
	}

	// Verify CA Cert
	if !caCert.IsCA {
		t.Error("CA certificate IsCA is false")
	}

	// Verify RCAC ID in Subject
	foundRCAC := false
	for _, name := range caCert.Subject.Names {
		if name.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}) {
			foundRCAC = true
			rv := name.Value.(string)
			// valname was marshaled as UTF8String, so rv should be the string directly if parsed by x509
			if rv != fmt.Sprintf("%016X", rcacID) {
				t.Errorf("expected RCAC ID %016X, got %s", rcacID, rv)
			}
		}
	}
	if !foundRCAC {
		t.Errorf("RCAC ID OID not found in CA certificate. Names: %+v", caCert.Subject.Names)
	}

	// 2. Provision Node Identity
	if err := cm.ProvisionNodeIdentity(nodeID); err != nil {
		t.Fatalf("ProvisionNodeIdentity failed: %v", err)
	}

	nodeCert, err := cm.GetNodeCertificate(nodeID)
	if err != nil {
		t.Fatalf("GetNodeCertificate failed: %v", err)
	}

	nodeKey, err := cm.GetNodePrivateKey(nodeID)
	if err != nil {
		t.Fatalf("GetNodePrivateKey failed: %v", err)
	}

	// Verify Node Cert Subject OIDs
	foundNodeID := false
	foundFabricID := false
	for _, name := range nodeCert.Subject.Names {
		if name.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}) {
			foundNodeID = true
			val := name.Value.(string)
			if val != fmt.Sprintf("%016X", nodeID) {
				t.Errorf("expected Node ID %016X, got %s", nodeID, val)
			}
		}
		if name.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}) {
			foundFabricID = true
			val := name.Value.(string)
			if val != fmt.Sprintf("%016X", fabricID) {
				t.Errorf("expected Fabric ID %016X, got %s", fabricID, val)
			}
		}
	}
	if !foundNodeID {
		t.Error("Node ID OID not found in node certificate")
	}
	if !foundFabricID {
		t.Error("Fabric ID OID not found in node certificate")
	}

	// 3. Verify Signature
	if err := nodeCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("node certificate signature verification failed: %v", err)
	}

	// Verify public key match
	if !nodeKey.PublicKey.Equal(nodeCert.PublicKey) {
		t.Error("node private key's public key does not match certificate public key")
	}
}

func TestDefaultCertificateManager_SignCertificate_ExternalKey(t *testing.T) {
	store := newMemoryStore()
	cm := NewDefaultCertificateManager(0x1, store)
	if err := cm.InitializeRootCA(1); err != nil {
		t.Fatalf("InitializeRootCA failed: %v", err)
	}

	externalPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nodeID := uint64(100)

	cert, err := cm.SignCertificate(&externalPriv.PublicKey, nodeID)
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	if !externalPriv.PublicKey.Equal(cert.PublicKey) {
		t.Error("signed certificate public key does not match provided public key")
	}

	caCert, _ := cm.GetCACertificate()
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("external key certificate signature verification failed: %v", err)
	}
}

func TestDefaultCertificateManagerStoresFilesInConfiguredDirectory(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "certs")
	store := NewFileCertificateStore(certDir)
	cm := NewDefaultCertificateManager(0x1234, store)

	if err := cm.InitializeRootCA(1); err != nil {
		t.Fatalf("InitializeRootCA() error = %v", err)
	}
	if err := cm.ProvisionNodeIdentity(0x42); err != nil {
		t.Fatalf("ProvisionNodeIdentity() error = %v", err)
	}

	// Verify expected files exist.
	for _, name := range []string{
		"ca-private.pem",
		"ca-cert.pem",
		"66-private.pem",
		"66-cert.pem",
	} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	// Verify that public key files are NOT created anymore (they are gone from the refactored code).
	for _, name := range []string{
		"ca-public.pem",
		"66-public.pem",
	} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err == nil {
			t.Fatalf("did NOT expect %s to exist anymore", name)
		}
	}
}

func TestDefaultCertificateManagerLoadReturnsMissingCAError(t *testing.T) {
	store := NewFileCertificateStore(t.TempDir())
	cm := NewDefaultCertificateManager(0x1234, store)

	err := cm.Load()
	if err == nil {
		t.Fatal("Load() error = nil, want missing CA error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() error = %v, want wrapped os.ErrNotExist", err)
	}
}

func TestDefaultCertificateManagerProvisionNodeIdentityReturnsSigningError(t *testing.T) {
	store := NewFileCertificateStore(t.TempDir())
	cm := NewDefaultCertificateManager(0x1234, store)

	err := cm.ProvisionNodeIdentity(0x42)
	if err == nil {
		t.Fatal("ProvisionNodeIdentity() error = nil, want signing error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ProvisionNodeIdentity() error = %v, want wrapped os.ErrNotExist", err)
	}
}
