package gomatter

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fabric structure represents matter Fabric.
// Its main parameters are Id of fabric and certificate manager.
type Fabric struct {
	id                 uint64
	CertificateManager CertificateManager
	ipk                []byte
}

func (fabric Fabric) Id() uint64 {
	return fabric.id
}

// CompressedFabric returns Compressed Fabric Identifier which is used to identify fabric
// in matter protocol.
func (fabric Fabric) CompressedFabric() []byte {
	capub := fabric.CertificateManager.GetCaPublicKey()
	caPublicKey := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	var fabricBigEndian bytes.Buffer
	binary.Write(&fabricBigEndian, binary.BigEndian, fabric.id)

	key := hkdfSHA256(caPublicKey[1:], fabricBigEndian.Bytes(), []byte("CompressedFabric"), 8)
	return key
}

func (fabric Fabric) makeIPK() []byte {
	key := hkdfSHA256(fabric.ipk, fabric.CompressedFabric(), []byte("GroupKey v1.0"), 16)
	return key
}

func (fabric Fabric) GetOperationalDeviceId(in uint64) string {
	compressedFabric := hex.EncodeToString(fabric.CompressedFabric())
	ids := fmt.Sprintf("%s-%016X", compressedFabric, in)
	return strings.ToUpper(ids)
}

// GenerateIPK creates a cryptographically secure random 16-byte IPK for callers
// that want helper generation without embedding the policy in NewFabric.
func GenerateIPK() ([]byte, error) {
	ipk := make([]byte, 16)
	_, err := rand.Read(ipk)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IPK: %w", err)
	}
	return ipk, nil
}

// NewFabric constructs new Fabric object and requires a caller-provided IPK.
// Callers must persist and pass the same 16-byte IPK to reload an existing fabric.
func NewFabric(id uint64, certman CertificateManager, ipk []byte) (*Fabric, error) {
	if len(ipk) != 16 {
		return nil, fmt.Errorf("IPK must be exactly 16 bytes, got %d", len(ipk))
	}
	ipk = append([]byte(nil), ipk...)

	out := &Fabric{
		id:                 id,
		CertificateManager: certman,
		ipk:                ipk,
	}
	return out, nil
}
