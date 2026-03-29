package gomatter

import (
	"bytes"
	"crypto/elliptic"
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

// NewFabric constructs new Fabric object.
func NewFabric(id uint64, certman CertificateManager) *Fabric {
	out := &Fabric{
		id:                 id,
		CertificateManager: certman,
		ipk:                []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
	}
	return out
}
