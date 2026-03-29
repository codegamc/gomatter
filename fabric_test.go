package gomatter

import (
	"crypto/ecdsa"
	"crypto/x509"
	"strings"
	"testing"
)

type stubCertificateManager struct{}

func (stubCertificateManager) GetCaPublicKey() ecdsa.PublicKey {
	return ecdsa.PublicKey{}
}

func (stubCertificateManager) GetCaCertificate() *x509.Certificate {
	return nil
}

func (stubCertificateManager) CreateUser(node_id uint64) error {
	return nil
}

func (stubCertificateManager) GetCertificate(id uint64) (*x509.Certificate, error) {
	return nil, nil
}

func (stubCertificateManager) GetPrivkey(id uint64) (*ecdsa.PrivateKey, error) {
	return nil, nil
}

func (stubCertificateManager) SignCertificate(user_pubkey *ecdsa.PublicKey, node_id uint64) (*x509.Certificate, error) {
	return nil, nil
}

func TestNewFabricStoresProvidedIPK(t *testing.T) {
	ipk := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

	fabric, err := NewFabric(0x1234, stubCertificateManager{}, ipk)
	if err != nil {
		t.Fatalf("NewFabric() error = %v", err)
	}

	if fabric.id != 0x1234 {
		t.Fatalf("fabric.id = 0x%x, want 0x1234", fabric.id)
	}
	if got := fabric.ipk; len(got) != len(ipk) {
		t.Fatalf("len(fabric.ipk) = %d, want %d", len(got), len(ipk))
	}
	for i := range ipk {
		if fabric.ipk[i] != ipk[i] {
			t.Fatalf("fabric.ipk[%d] = %d, want %d", i, fabric.ipk[i], ipk[i])
		}
	}
}

func TestNewFabricCopiesProvidedIPK(t *testing.T) {
	ipk := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

	fabric, err := NewFabric(0x1234, stubCertificateManager{}, ipk)
	if err != nil {
		t.Fatalf("NewFabric() error = %v", err)
	}

	ipk[0] = 0xff
	if fabric.ipk[0] == ipk[0] {
		t.Fatal("fabric.ipk shares backing storage with provided IPK")
	}
}

func TestNewFabricRejectsInvalidIPKLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		ipk  []byte
		want string
	}{
		{name: "nil", ipk: nil, want: "got 0"},
		{name: "short", ipk: make([]byte, 15), want: "got 15"},
		{name: "long", ipk: make([]byte, 17), want: "got 17"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fabric, err := NewFabric(0x1234, stubCertificateManager{}, tc.ipk)
			if err == nil {
				t.Fatalf("NewFabric() error = nil, fabric = %#v", fabric)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewFabric() error = %v, want message containing %q", err, tc.want)
			}
		})
	}
}

func TestGenerateIPK(t *testing.T) {
	ipk, err := GenerateIPK()
	if err != nil {
		t.Fatalf("GenerateIPK() error = %v", err)
	}
	if len(ipk) != 16 {
		t.Fatalf("len(GenerateIPK()) = %d, want 16", len(ipk))
	}
	if ipk == nil {
		t.Fatal("GenerateIPK() = nil, want 16-byte IPK")
	}
}
