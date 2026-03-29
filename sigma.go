package gomatter

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"

	"github.com/codegamc/gomatter/ccm"
	"github.com/codegamc/gomatter/mattertlv"
)

type sigmaContext struct {
	sessionPrivkey              *ecdh.PrivateKey
	session                     int
	controllerKey               *ecdsa.PrivateKey
	controllerMatterCertificate []byte

	i2rKey []byte
	r2iKey []byte

	sigma2Dec     DecodedGeneric
	sigma1Payload []byte
	exchange      uint16
}

func (sc *sigmaContext) genSigma1(fabric *Fabric, deviceID uint64) {
	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()

	initiatorRandom := make([]byte, 32)
	rand.Read(initiatorRandom)
	tlvx.WriteOctetString(1, initiatorRandom)

	sessionId := 222
	tlvx.WriteUInt(2, mattertlv.TYPE_UINT_2, uint64(sessionId))

	var destinationMessage bytes.Buffer
	destinationMessage.Write(initiatorRandom)
	//cacert := ca.LoadCert("ca-cert.pem")
	cacert := fabric.CertificateManager.GetCaCertificate()
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	caPublicKey := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	destinationMessage.Write(caPublicKey)

	var fabricID uint64
	fabricID = fabric.id
	binary.Write(&destinationMessage, binary.LittleEndian, fabricID)

	var node uint64
	node = deviceID
	binary.Write(&destinationMessage, binary.LittleEndian, node)

	key := fabric.makeIPK()

	destinationIdentifier := hmacSHA256Enc(destinationMessage.Bytes(), key)

	tlvx.WriteOctetString(3, destinationIdentifier)

	tlvx.WriteOctetString(4, sc.sessionPrivkey.PublicKey().Bytes())
	tlvx.WriteStructEnd()
	sc.sigma1Payload = tlvx.Bytes()
}

func genSigma1Req2(payload []byte, exchange uint16) []byte {
	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        0x30, //sigma1
		ExchangeId:    exchange,
		ProtocolId:    0x00,
	}
	prot.Encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}

func genSigma3Req2(payload []byte, exchange uint16) []byte {
	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        0x32, //sigma1
		ExchangeId:    exchange,
		ProtocolId:    0x00}

	prot.Encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}

func (sc *sigmaContext) sigma3(fabric *Fabric) ([]byte, error) {
	var tlvS3TBS mattertlv.TLVBuffer
	tlvS3TBS.WriteAnonStruct()
	tlvS3TBS.WriteOctetString(1, sc.controllerMatterCertificate)
	tlvS3TBS.WriteOctetString(3, sc.sessionPrivkey.PublicKey().Bytes())
	responderPublic := sc.sigma2Dec.Tlv.GetOctetStringRec([]int{3})
	sigma2ResponderSession, err := sc.sigma2Dec.Tlv.GetIntRec([]int{2})
	if err != nil {
		return []byte{}, err
	}
	tlvS3TBS.WriteOctetString(4, responderPublic)
	tlvS3TBS.WriteStructEnd()
	//log.Printf("responder public %s\n", hex.EncodeToString(responderPublic))

	tlvS3TBSHash := sha256Enc(tlvS3TBS.Bytes())
	sr, ss, err := ecdsa.Sign(rand.Reader, sc.controllerKey, tlvS3TBSHash)
	if err != nil {
		return []byte{}, err
	}
	tlvS3TBSOut := append(sr.Bytes(), ss.Bytes()...)

	var tlvS3TBE mattertlv.TLVBuffer
	tlvS3TBE.WriteAnonStruct()
	tlvS3TBE.WriteOctetString(1, sc.controllerMatterCertificate)
	tlvS3TBE.WriteOctetString(3, tlvS3TBSOut)
	tlvS3TBE.WriteStructEnd()

	pub, err := ecdh.P256().NewPublicKey(responderPublic)
	if err != nil {
		return []byte{}, err
	}
	sharedSecret, err := sc.sessionPrivkey.ECDH(pub)
	if err != nil {
		return []byte{}, err
	}
	s3KTranscript := sc.sigma1Payload
	s3KTranscript = append(s3KTranscript, sc.sigma2Dec.Payload...)

	transcriptHash := sha256Enc(s3KTranscript)
	s3Salt := fabric.makeIPK()
	s3Salt = append(s3Salt, transcriptHash...)

	s3Key := hkdfSHA256(sharedSecret, s3Salt, []byte("Sigma3"), 16)

	c, err := aes.NewCipher(s3Key)
	if err != nil {
		return []byte{}, err
	}
	nonce := []byte("NCASE_Sigma3N")
	ccm, err := ccm.NewCCM(c, 16, len(nonce))
	if err != nil {
		return []byte{}, err
	}
	cipherText := ccm.Seal(nil, nonce, tlvS3TBE.Bytes(), []byte{})

	var tlvS3 mattertlv.TLVBuffer
	tlvS3.WriteAnonStruct()
	tlvS3.WriteOctetString(1, cipherText)
	tlvS3.WriteStructEnd()

	toSend := genSigma3Req2(tlvS3.Bytes(), sc.exchange)

	// prepare session keys
	sessionKeyTranscript := s3KTranscript
	sessionKeyTranscript = append(sessionKeyTranscript, tlvS3.Bytes()...)
	transcriptHash = sha256Enc(sessionKeyTranscript)
	salt := fabric.makeIPK()
	salt = append(salt, transcriptHash...)

	keypack := hkdfSHA256(sharedSecret, salt, []byte("SessionKeys"), 16*3)
	sc.session = sigma2ResponderSession

	sc.i2rKey = keypack[:16]
	sc.r2iKey = keypack[16:32]

	return toSend, nil
}
