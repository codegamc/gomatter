package gomatter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sync"
	"time"
)

// DefaultCertificateManager implements CertificateManager using a CertificateStore.
type DefaultCertificateManager struct {
	fabric        uint64
	store         CertificateStore
	caCertificate *x509.Certificate
	caPrivateKey  *ecdsa.PrivateKey
	mu            sync.Mutex
}

// NewDefaultCertificateManager creates a manager with the given fabric ID and storage backend.
func NewDefaultCertificateManager(fabric uint64, store CertificateStore) *DefaultCertificateManager {
	cm := &DefaultCertificateManager{fabric: fabric, store: store}
	// Load CA data during construction.
	_ = cm.Load()
	return cm
}


func (cm *DefaultCertificateManager) GetCAPublicKey() (ecdsa.PublicKey, error) {
	return cm.caPrivateKey.PublicKey, nil
}

func (cm *DefaultCertificateManager) GetCACertificate() (*x509.Certificate, error) {
	return cm.caCertificate, nil
}

// Load initializes CA by loading required state from the store.
func (cm *DefaultCertificateManager) Load() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	pk, err := cm.store.LoadPrivateKey("ca")
	if err != nil {
		return fmt.Errorf("load CA private key: %w", err)
	}
	cert, err := cm.store.LoadCertificate("ca")
	if err != nil {
		return fmt.Errorf("load CA certificate: %w", err)
	}
	cm.caPrivateKey = pk
	cm.caCertificate = cert
	return nil
}

// InitializeRootCA sets up the Root Certificate Authority for the fabric.
func (cm *DefaultCertificateManager) InitializeRootCA(rcacID uint64) error {
	// If CA already exists, just load it.
	_, err := cm.store.LoadPrivateKey("ca")
	if err == nil {
		// CA already present, load into manager.
		return cm.Load()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check CA key: %w", err)
	}
	// Generate CA private key and store it.
	priv, err := cm.generateAndStoreKey("ca")
	if err != nil {
		return err
	}
	// Create CA certificate and store it.
	err = cm.createCaCert(rcacID, priv)
	if err != nil {
		return err
	}
	// Load into manager.
	return cm.Load()
}

// ProvisionNodeIdentity creates keys and certificate for node with specific id.
func (cm *DefaultCertificateManager) ProvisionNodeIdentity(nodeId uint64) error {
	if cm.caPrivateKey == nil {
		if err := cm.Load(); err != nil {
			return err
		}
	}
	name := fmt.Sprintf("%d", nodeId)
	// Generate node private key and store it.
	priv, err := cm.generateAndStoreKey(name)
	if err != nil {
		return err
	}
	// Sign certificate for the node.
	_, err = cm.SignCertificate(&priv.PublicKey, nodeId)
	return err
}

func (cm *DefaultCertificateManager) SignCertificate(userPublicKey *ecdsa.PublicKey, nodeId uint64) (*x509.Certificate, error) {
	if cm.caPrivateKey == nil {
		return nil, errors.New("CA not loaded")
	}
	nodeName := fmt.Sprintf("%d", nodeId)

	publicKeyAuth := elliptic.Marshal(elliptic.P256(), cm.caPrivateKey.PublicKey.X, cm.caPrivateKey.PublicKey.Y)
	sh := sha1.New()
	sh.Write(publicKeyAuth)
	shaAuth := sh.Sum(nil)

	publicKeySubj2 := elliptic.Marshal(elliptic.P256(), userPublicKey.X, userPublicKey.Y)
	shp := sha1.New()
	shp.Write(publicKeySubj2)
	shaSubj := shp.Sum(nil)

	subj := pkix.Name{}
	nodeIDString := fmt.Sprintf("%016X", nodeId)
	valname, err := asn1.MarshalWithParams(nodeIDString, "utf8")
	if err != nil {
		return nil, err
	}
	fabricString := fmt.Sprintf("%016X", cm.fabric)
	valnameFabric, err := asn1.MarshalWithParams(fabricString, "utf8")
	if err != nil {
		return nil, err
	}
	subj.ExtraNames = []pkix.AttributeTypeAndValue{
		{
			Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1},
			Value: asn1.RawValue{FullBytes: valname},
		},
		{
			Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5},
			Value: asn1.RawValue{FullBytes: valnameFabric},
		},
	}

	var template x509.Certificate
	template.Version = 3
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().AddDate(1, 0, 0)
	template.Subject = subj
	template.IsCA = false
	template.SerialNumber = big.NewInt(10001)

	// Extensions (order matters for Matter compatibility).
	extkeyusa, _ := hex.DecodeString("301406082B0601050507030206082B06010505070301")
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // basic constraints
			Critical: true,
			Value:    []byte{0x30, 0x03, 0x01, 0x01, 0xff},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // keyUsage
			Critical: true,
			Value:    []byte{3, 2, 7, 0x80},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // ExtkeyUsage
			Critical: true,
			Value:    extkeyusa,
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 14}, // subjectKeyId
			Critical: false,
			Value:    append([]byte{0x04, 0x14}, shaSubj...),
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 35}, // authorityKeyId
			Critical: false,
			Value:    append([]byte{0x30, 0x16, 0x80, 0x14}, shaAuth...),
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, cm.caCertificate, userPublicKey, cm.caPrivateKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	if err := cm.store.SaveCertificate(nodeName, parsed); err != nil {
		return nil, err
	}
	log.Printf("Signed certificate for node 0x%x\n", nodeId)
	return parsed, nil
}

func (cm *DefaultCertificateManager) generateAndStoreKey(name string) (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := cm.store.SavePrivateKey(name, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func (cm *DefaultCertificateManager) createCaCert(rcacID uint64, priv *ecdsa.PrivateKey) error {
	rcacIDString := fmt.Sprintf("%016X", rcacID)
	valname, err := asn1.MarshalWithParams(rcacIDString, "utf8")
	if err != nil {
		return err
	}
	subj := pkix.Name{}
	subj.ExtraNames = []pkix.AttributeTypeAndValue{{
		Type:  asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4},
		Value: asn1.RawValue{FullBytes: valname},
	}}

	var template x509.Certificate
	template.Version = 3
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().AddDate(1, 0, 0)
	template.Subject = subj
	template.IsCA = true
	template.SerialNumber = big.NewInt(10000)
	template.Issuer = subj

	sha := sha1.New()
	sha.Write(elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y))
	shaBytes := sha.Sum(nil)

	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // basic constraints
			Critical: true,
			Value:    []byte{0x30, 0x03, 0x01, 0x01, 0xff},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // keyUsage
			Critical: true,
			Value:    []byte{3, 2, 1, 6},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 14}, // subjectKeyId
			Critical: false,
			Value:    append([]byte{0x04, 0x14}, shaBytes...),
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 35}, // authorityKeyId
			Critical: false,
			Value:    append([]byte{0x30, 0x16, 0x80, 0x14}, shaBytes...),
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	return cm.store.SaveCertificate("ca", cert)
}

func (cm *DefaultCertificateManager) GetNodePrivateKey(nodeId uint64) (*ecdsa.PrivateKey, error) {
	return cm.store.LoadPrivateKey(fmt.Sprintf("%d", nodeId))
}

func (cm *DefaultCertificateManager) GetNodeCertificate(nodeId uint64) (*x509.Certificate, error) {
	return cm.store.LoadCertificate(fmt.Sprintf("%d", nodeId))
}
