package gomatter

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/codegamc/gomatter/ccm"
	"github.com/codegamc/gomatter/mattertlv"
)

type udpChannel struct {
	Udp           net.PacketConn
	RemoteAddress net.UDPAddr
}

func startUDPChannel(remoteIP net.IP, remotePort, localPort int) (*udpChannel, error) {
	var out *udpChannel = new(udpChannel)
	out.RemoteAddress = net.UDPAddr{
		IP:   remoteIP,
		Port: remotePort,
	}
	var err error
	out.Udp, err = net.ListenPacket("udp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (ch *udpChannel) send(data []byte) error {
	_, err := ch.Udp.WriteTo(data, &ch.RemoteAddress)
	return err
}
func (ch *udpChannel) receive() ([]byte, error) {
	buf := make([]byte, 1024*10)
	n, _, errx := ch.Udp.ReadFrom(buf)
	if errx != nil {
		return []byte{}, errx
	}
	return buf[:n], nil
}

func makeNonce3(counter uint32, node []byte) []byte {
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write(node)
	return n.Bytes()
}

type SecureChannel struct {
	Udp            *udpChannel
	encryptKey     []byte
	decryptKey     []byte
	remoteNode     []byte
	localNode      []byte
	Counter        uint32
	session        int
	receiveTimeout time.Duration
}

const defaultReceiveTimeout = 3 * time.Second

func newSecureChannel(udp *udpChannel) *SecureChannel {
	return &SecureChannel{
		Udp:            udp,
		receiveTimeout: defaultReceiveTimeout,
	}
}

// StartSecureChannel initializes secure channel for plain unencrypted communication.
// It initializes UDP interface and blocks local udp port.
// Secure channel becomes encrypted after encryption keys are supplied.
func StartSecureChannel(remoteIP net.IP, remotePort, localPort int) (*SecureChannel, error) {
	udp, err := startUDPChannel(remoteIP, remotePort, localPort)
	if err != nil {
		return nil, err
	}
	sc := newSecureChannel(udp)
	sc.Counter = uint32(rand.Intn(0xffffffff))
	return sc, nil
}

func (sc *SecureChannel) Receive(ctx context.Context) (DecodedGeneric, error) {
	return sc.receiveWithContext(ctx, sc.receiveTimeout)
}

func (sc *SecureChannel) ReceiveWithTimeout(timeout time.Duration) (DecodedGeneric, error) {
	return sc.receiveWithContext(context.Background(), timeout)
}

func (sc *SecureChannel) receiveWithContext(ctx context.Context, timeout time.Duration) (DecodedGeneric, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return DecodedGeneric{}, err
	}

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	if err := sc.Udp.Udp.SetReadDeadline(deadline); err != nil {
		return DecodedGeneric{}, err
	}

	stop := context.AfterFunc(ctx, func() {
		_ = sc.Udp.Udp.SetReadDeadline(time.Now())
	})
	defer stop()

	out, err := sc.receive(ctx)
	if err != nil && ctx.Err() != nil {
		return DecodedGeneric{}, ctx.Err()
	}
	return out, err
}

func (sc *SecureChannel) ReceiveBlocking() (DecodedGeneric, error) {
	return sc.ReceiveWithTimeout(0)
}

func (sc *SecureChannel) SetReceiveTimeout(timeout time.Duration) {
	sc.receiveTimeout = timeout
}

func (sc *SecureChannel) receive(ctx context.Context) (DecodedGeneric, error) {
	data, err := sc.Udp.receive()
	if err != nil {
		return DecodedGeneric{}, err
	}
	decode_buffer := bytes.NewBuffer(data)
	var out DecodedGeneric
	out.MessageHeader.Decode(decode_buffer)
	add := data[:len(data)-decode_buffer.Len()]
	proto := decode_buffer.Bytes()

	if len(sc.decryptKey) > 0 {
		nonce := makeNonce3(out.MessageHeader.messageCounter, sc.remoteNode)
		c, err := aes.NewCipher(sc.decryptKey)
		if err != nil {
			return DecodedGeneric{}, err
		}
		ccm, err := ccm.NewCCM(c, 16, len(nonce))
		if err != nil {
			return DecodedGeneric{}, err
		}
		ciphertext := proto
		decbuf := []byte{}
		outx, err := ccm.Open(decbuf, nonce, ciphertext, add)
		if err != nil {
			return DecodedGeneric{}, err
		}

		decoder := bytes.NewBuffer(outx)

		out.ProtocolHeader.Decode(decoder)
		if len(decoder.Bytes()) > 0 {
			tlvdata := make([]byte, decoder.Len())
			n, _ := decoder.Read(tlvdata)
			out.Payload = tlvdata[:n]
		}
	} else {
		out.ProtocolHeader.Decode(decode_buffer)
		if len(decode_buffer.Bytes()) > 0 {
			tlvdata := make([]byte, decode_buffer.Len())
			n, _ := decode_buffer.Read(tlvdata)
			out.Payload = tlvdata[:n]
		}
	}

	if out.ProtocolHeader.ProtocolId == 0 {
		if out.ProtocolHeader.Opcode == SecChanOpcodeAck { // standalone ack
			return sc.receive(ctx)
		}
	}

	ack := ackGen(out.ProtocolHeader, out.MessageHeader.messageCounter)
	sc.Send(ack)

	if out.ProtocolHeader.ProtocolId == 0 {
		if out.ProtocolHeader.Opcode == SecChanOpcodeStatusRep { // status report
			buf := bytes.NewBuffer(out.Payload)
			binary.Read(buf, binary.LittleEndian, &out.StatusReport.GeneralCode)
			binary.Read(buf, binary.LittleEndian, &out.StatusReport.ProtocolId)
			binary.Read(buf, binary.LittleEndian, &out.StatusReport.ProtocolCode)
			return out, nil
		}
	}
	if len(out.Payload) > 0 {
		out.Tlv = mattertlv.Decode(out.Payload)
	}
	return out, nil
}

// Send sends Protocol Message via secure channel. It creates Matter Message by adding Message Header.
// Protocol Message is aes-ccm encrypted when channel does have encryption keys.
// When encryption keys are empty plain Message is sent.
func (sc *SecureChannel) Send(data []byte) error {

	sc.Counter = sc.Counter + 1
	var buffer bytes.Buffer
	msg := MessageHeader{
		sessionId:      uint16(sc.session),
		securityFlags:  0,
		messageCounter: sc.Counter,
		sourceNodeId:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	msg.Encode(&buffer)
	if len(sc.encryptKey) == 0 {
		buffer.Write(data)
	} else {
		headerSlice := buffer.Bytes()
		add2 := make([]byte, len(headerSlice))
		copy(add2, headerSlice)

		nonce := makeNonce3(sc.Counter, sc.localNode)

		c, err := aes.NewCipher(sc.encryptKey)
		if err != nil {
			return err
		}
		ccm, err := ccm.NewCCM(c, 16, len(nonce))
		if err != nil {
			return err
		}
		CipherText := ccm.Seal(nil, nonce, data, add2)
		buffer.Write(CipherText)
	}

	err := sc.Udp.send(buffer.Bytes())
	return err
}

// Close secure channel. Send close session message to remote end and relase UDP port.
func (sc *SecureChannel) Close() {
	if sc.Udp == nil || sc.Udp.Udp == nil {
		return
	}
	sr := EncodeStatusReport(StatusReportElements{
		GeneralCode:  0,
		ProtocolId:   0,
		ProtocolCode: 3, //close session
	})
	sc.Send(sr)
	sc.Udp.Udp.Close()
}
