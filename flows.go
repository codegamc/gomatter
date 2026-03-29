package gomatter

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	randm "math/rand"
	"net"
	"time"

	"github.com/codegamc/gomatter/mattertlv"
)

// spake2pExchange establishes secure session using PASE (Passcode-Authenticated Session Establishment).
// This uses SPAKE2+ protocol
func spake2pExchange(ctx context.Context, pin int, udp *udpChannel, receiveTimeout time.Duration) (*SecureChannel, error) {
	exchange := uint16(randm.Intn(0xffff))
	secureChannel := newSecureChannel(udp)
	secureChannel.SetReceiveTimeout(receiveTimeout)
	secureChannel.session = 0
	secureChannel.Counter = uint32(randm.Intn(0xffffffff))

	pbkdfRequest := pBKDFParamRequest(exchange)
	secureChannel.Send(pbkdfRequest)

	pbkdfResponseS, err := secureChannel.Receive(ctx)
	if err != nil {
		return nil, fmt.Errorf("pbkdf response not received: %s", err.Error())
	}
	if pbkdfResponseS.ProtocolHeader.Opcode != SecChanOpcodePBKDFResp {
		return nil, fmt.Errorf("SecChanOpcodePBKDFResp not received")
	}
	pbkdfResponseSalt := pbkdfResponseS.Tlv.GetOctetStringRec([]int{4, 2})
	pbkdfResponseIterations, err := pbkdfResponseS.Tlv.GetIntRec([]int{4, 1})
	if err != nil {
		return nil, fmt.Errorf("can't get pbkdf_response_iterations")
	}
	pbkdfResponseSession, err := pbkdfResponseS.Tlv.GetIntRec([]int{3})
	if err != nil {
		return nil, fmt.Errorf("can't get pbkdf_response_session")
	}

	sctx := NewSpakeCtx()
	sctx.GenerateW(pin, pbkdfResponseSalt, pbkdfResponseIterations)
	sctx.GenerateRandomX()
	sctx.CalculateX()

	pake1 := pake1ParamRequest(exchange, sctx.X.AsBytes())
	secureChannel.Send(pake1)

	pake2s, err := secureChannel.Receive(ctx)
	if err != nil {
		return nil, fmt.Errorf("pake2 not received: %s", err.Error())
	}
	if pake2s.ProtocolHeader.Opcode != SecChanOpcodePAKE2 {
		return nil, fmt.Errorf("SecChanOpcodePAKE2 not received")
	}
	//pake2s.tlv.Dump(1)
	pake2PB := pake2s.Tlv.GetOctetStringRec([]int{1})

	sctx.Y.fromBytes(pake2PB)
	sctx.calculateZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdfRequest[6:]...) // 6 is size of proto header
	ttseed = append(ttseed, pbkdfResponseS.Payload...)
	err = sctx.calculateHash(ttseed)
	if err != nil {
		return nil, err
	}

	pake3 := pake3ParamRequest(exchange, sctx.cA)
	secureChannel.Send(pake3)

	statusReport, err := secureChannel.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if statusReport.StatusReport.ProtocolCode != 0 {
		return nil, fmt.Errorf("pake3 is not success code: %d", statusReport.StatusReport.ProtocolCode)
	}

	secureChannel = newSecureChannel(udp)
	secureChannel.SetReceiveTimeout(receiveTimeout)
	secureChannel.decryptKey = sctx.decryptKey
	secureChannel.encryptKey = sctx.encryptKey
	secureChannel.remoteNode = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	secureChannel.localNode = []byte{0, 0, 0, 0, 0, 0, 0, 0}
	secureChannel.session = pbkdfResponseSession

	return secureChannel, nil
}

// SigmaExhange establishes secure session using CASE (Certificate Authenticated Session Establishment)
func SigmaExchange(ctx context.Context, fabric *Fabric, controllerID uint64, deviceID uint64, secureChannel *SecureChannel) (*SecureChannel, error) {

	controllerPrivkey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigmaContext := sigmaContext{
		sessionPrivkey: controllerPrivkey,
		exchange:       uint16(randm.Intn(0xffff)),
	}
	sigmaContext.genSigma1(fabric, deviceID)
	sigma1 := genSigma1Req2(sigmaContext.sigma1Payload, sigmaContext.exchange)
	secureChannel.Send(sigma1)

	var err error
	sigmaContext.sigma2Dec, err = secureChannel.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if (sigmaContext.sigma2Dec.ProtocolHeader.ProtocolId == ProtocolIdSecureChannel) &&
		(sigmaContext.sigma2Dec.ProtocolHeader.Opcode == SecChanOpcodeStatusRep) {
		return nil, fmt.Errorf("sigma2 not received. status: %x %x", sigmaContext.sigma2Dec.StatusReport.GeneralCode,
			sigmaContext.sigma2Dec.StatusReport.ProtocolCode)
	}
	if sigmaContext.sigma2Dec.ProtocolHeader.Opcode != 0x31 {
		return nil, fmt.Errorf("sigma2 not received")
	}

	sigmaContext.controllerKey, err = fabric.CertificateManager.GetPrivkey(controllerID)
	if err != nil {
		return nil, err
	}
	controllerCert, err := fabric.CertificateManager.GetCertificate(controllerID)
	if err != nil {
		return nil, err
	}
	sigmaContext.controllerMatterCertificate = SerializeCertificateIntoMatter(fabric, controllerCert)

	toSend, err := sigmaContext.sigma3(fabric)
	if err != nil {
		return nil, err
	}
	secureChannel.Send(toSend)

	sigmaResult, err := secureChannel.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if sigmaResult.ProtocolHeader.Opcode != SecChanOpcodeStatusRep {
		return nil, fmt.Errorf("unexpected message (opcode:0x%x)", sigmaResult.ProtocolHeader.Opcode)
	}
	if !sigmaResult.StatusReport.IsOk() {
		return nil, fmt.Errorf("sigma result is not ok %d %d %d",
			sigmaResult.StatusReport.GeneralCode,
			sigmaResult.StatusReport.ProtocolId, sigmaResult.StatusReport.ProtocolCode)
	}

	secureChannel.decryptKey = sigmaContext.r2iKey
	secureChannel.encryptKey = sigmaContext.i2rKey
	secureChannel.remoteNode = idToBytes(deviceID)
	secureChannel.localNode = idToBytes(controllerID)
	secureChannel.session = sigmaContext.session
	return secureChannel, nil
}

// Commission performs commissioning procedure on device with deviceIP ip address.
//   - fabric is fabric object with approriate certificate authority
//   - pin is passcode used for device pairing
//   - controllerID is identifier of node whioch will be owner/admin of this device
//   - deviceID is identifier of "new" device
func Commission(ctx context.Context, fabric *Fabric, deviceIP net.IP, pin int, controllerID, deviceID uint64, opts ...Option) error {
	o := applyOptions(opts)

	channel, err := startUDPChannel(deviceIP, o.remotePort, o.localPort)
	if err != nil {
		return err
	}
	secureChannel := newSecureChannel(channel)
	secureChannel.SetReceiveTimeout(o.receiveTimeout)
	defer secureChannel.Close()

	secureChannel, err = spake2pExchange(ctx, pin, channel, o.receiveTimeout)
	if err != nil {
		return err
	}

	// send csr request
	var tlvb mattertlv.TLVBuffer
	tlvb.WriteOctetString(0, CreateRandomBytes(32))
	toSend := EncodeIMInvokeRequest(0, 0x3e, 4, tlvb.Bytes(), false, uint16(randm.Intn(0xffff)))
	secureChannel.Send(toSend)

	csrResp, err := secureChannel.Receive(ctx)
	if err != nil {
		return err
	}

	nocsr := csrResp.Tlv.GetOctetStringRec([]int{1, 0, 0, 1, 0})
	if len(nocsr) == 0 {
		return fmt.Errorf("nocsr not received")
	}
	tlv2 := mattertlv.Decode(nocsr)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return err
	}

	//AddTrustedRootCertificate
	var tlv4 mattertlv.TLVBuffer
	tlv4.WriteOctetString(0, SerializeCertificateIntoMatter(fabric, fabric.CertificateManager.GetCaCertificate()))
	toSend = EncodeIMInvokeRequest(0, 0x3e, 0xb, tlv4.Bytes(), false, uint16(randm.Intn(0xffff)))
	secureChannel.Send(toSend)

	resp, err := secureChannel.Receive(ctx)
	if err != nil {
		return err
	}
	resp_status, err := ParseImInvokeResponse(&resp.Tlv)
	if err != nil {
		return fmt.Errorf("unexpected status to AddTrustedRootCertificate: %w", err)
	}
	if resp_status != 0 {
		return fmt.Errorf("unexpected status to AddTrustedRootCertificate %d", resp_status)
	}

	//noc_x509 := sign_cert(csrp, 2, "user")
	nocX509, err := fabric.CertificateManager.SignCertificate(csrp.PublicKey.(*ecdsa.PublicKey), deviceID)
	if err != nil {
		return err
	}
	nocMatter := SerializeCertificateIntoMatter(fabric, nocX509)
	//AddNOC
	var tlv5 mattertlv.TLVBuffer
	tlv5.WriteOctetString(0, nocMatter)
	tlv5.WriteOctetString(2, fabric.ipk) //ipk
	tlv5.WriteUInt64(3, controllerID)    // admin subject !
	tlv5.WriteUInt16(4, 101)             // admin vendorid ??
	toSend = EncodeIMInvokeRequest(0, 0x3e, 0x6, tlv5.Bytes(), false, uint16(randm.Intn(0xffff)))

	secureChannel.Send(toSend)

	resp, err = secureChannel.Receive(ctx)
	if err != nil {
		return err
	}
	resp_status_add_noc, err := resp.Tlv.GetIntRec([]int{1, 0, 0, 1, 0})
	if err != nil {
		return fmt.Errorf("error during AddNOC %s", err.Error())
	}
	if resp_status_add_noc != 0 {
		return fmt.Errorf("unexpected status to AddNOC %d", resp_status_add_noc)
	}

	secureChannel.decryptKey = []byte{}
	secureChannel.encryptKey = []byte{}
	secureChannel.session = 0

	secureChannel, err = SigmaExchange(ctx, fabric, controllerID, deviceID, secureChannel)
	if err != nil {
		return err
	}

	//commissioning complete
	toSend = EncodeIMInvokeRequest(0, 0x30, 4, []byte{}, false, uint16(randm.Intn(0xffff)))
	secureChannel.Send(toSend)

	respx, err := secureChannel.Receive(ctx)
	if err != nil {
		return err
	}
	commissioning_result, err := respx.Tlv.GetIntRec([]int{1, 0, 0, 1, 0})
	if err != nil {
		return err
	}
	if commissioning_result == 0 {
		log.Printf("commissioning OK\n")
	} else {
		log.Printf("commissioning error: %d\n", commissioning_result)
	}
	return nil
}

func ConnectDevice(ctx context.Context, deviceIP net.IP, port int, fabric *Fabric, deviceID, adminID uint64, opts ...Option) (*SecureChannel, error) {
	o := applyOptions(opts)
	var secureChannel *SecureChannel
	var err error
	if secureChannel, err = StartSecureChannel(deviceIP, port, o.localPort); err != nil {
		return nil, err
	}
	secureChannel.SetReceiveTimeout(o.receiveTimeout)
	if secureChannel, err = SigmaExchange(ctx, fabric, adminID, deviceID, secureChannel); err != nil {
		return nil, err
	}
	return secureChannel, nil
}
