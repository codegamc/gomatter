// this is example application which shows how to:
// - create fabric (generate CA certificate)
// - commission device (upload certificates to it)
// - send commands to device
// device parameters (ip address and passcode) are hardcoded in main function
// this example assumes that device is in state accepting new commissioning
// This example also hard-codes the IPK so it can reload an existing fabric.
// Real callers should persist and pass their own IPK.

package main

import (
	"context"
	"math/rand"
	"net"

	gomatter "github.com/codegamc/gomatter"
	"github.com/codegamc/gomatter/mattertlv"
	"github.com/codegamc/gomatter/symbols"
)

var demoIPK = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}

func bootstrapCA(fabricID, adminUser uint64) {
	cm := gomatter.NewFileCertManager(fabricID, gomatter.FileCertManagerConfig{})
	cm.BootstrapCa()
	cm.Load()
	if err := cm.CreateUser(adminUser); err != nil {
		panic(err)
	}
}

func loadFabric(fabricID uint64) *gomatter.Fabric {
	cm := gomatter.NewFileCertManager(fabricID, gomatter.FileCertManagerConfig{})
	cm.Load()
	fabric, err := gomatter.NewFabric(fabricID, cm, demoIPK)
	if err != nil {
		panic(err)
	}
	return fabric
}

func commission(fabricID, adminUser, deviceID uint64, deviceIP string, pin int) {
	fabric := loadFabric(fabricID)
	if err := gomatter.Commission(context.Background(), fabric, net.ParseIP(deviceIP), pin, adminUser, deviceID); err != nil {
		panic(err)
	}
}

func sendOnCommand(secureChannel *gomatter.SecureChannel) {
	onCommand := gomatter.EncodeIMInvokeRequest(
		1,                           // endpoint
		symbols.CLUSTER_ID_OnOff,    // api cluster (on/off)
		symbols.COMMAND_ID_OnOff_On, // on command
		[]byte{},                    // no extra data
		false, uint16(rand.Uint32()))

	secureChannel.Send(onCommand)

	// process ON command response
	response, err := secureChannel.Receive(context.Background())
	if err != nil {
		panic(err)
	}
	if response.ProtocolHeader.Opcode != gomatter.InteractionOpcodeInvokeRsp {
		panic("unexpected message")
	}
	if status, err := gomatter.ParseImInvokeResponse(&response.Tlv); err != nil || status != 0 {
		response.Tlv.Dump(0)
		panic("response was not OK")
	}
}

func sendColorCommand(secureChannel *gomatter.SecureChannel) {
	var tlv mattertlv.TLVBuffer
	tlv.WriteUInt8(0, 100) // hue
	tlv.WriteUInt8(1, 200) // saturation
	tlv.WriteUInt8(2, 10)  // time
	colorCommand := gomatter.EncodeIMInvokeRequest(
		1,                               // endpoint
		symbols.CLUSTER_ID_ColorControl, // color control cluster
		symbols.COMMAND_ID_ColorControl_MoveToHueAndSaturation,
		tlv.Bytes(),
		false, uint16(rand.Uint32()))

	secureChannel.Send(colorCommand)

	// process command response
	response, err := secureChannel.Receive(context.Background())
	if err != nil {
		panic(err)
	}
	if response.ProtocolHeader.Opcode != gomatter.InteractionOpcodeInvokeRsp {
		panic("unexpected message")
	}
	if status, err := gomatter.ParseImInvokeResponse(&response.Tlv); err != nil || status != 0 {
		response.Tlv.Dump(0)
		panic("response was not OK")
	}
}

func main() {
	var fabricID uint64 = 0x100
	var adminUser uint64 = 5
	var deviceID uint64 = 10
	deviceIP := "192.168.5.178"
	pin := 123456

	// Generate CA keys/certificate + admin user
	// do this only once for your fabric
	bootstrapCA(fabricID, adminUser)

	// Commission device - upload certificates + set admin user
	// do this once for device (per fabric)
	commission(fabricID, adminUser, deviceID, deviceIP, pin)

	// connect to commissioned device
	fabric := loadFabric(fabricID)
	secureChannel, err := gomatter.ConnectDevice(context.Background(), net.ParseIP(deviceIP), 5540, fabric, deviceID, adminUser)
	if err != nil {
		panic(err)
	}
	defer secureChannel.Close()

	// send ON command
	sendOnCommand(secureChannel)

	// send set color command
	sendColorCommand(secureChannel)
}
