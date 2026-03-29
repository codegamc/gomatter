// this is example application which shows how to:
// - create fabric (generate CA certificate)
// - commission device (upload certificates to it)
// - send commands to device
// devica parameters (ip address and passcode) are hardcoded in main function
// this example assumes that device is in state accepting new commissioning

package main

import (
	"context"
	"math/rand"
	"net"

	"github.com/codegamc/gomatter"
	"github.com/codegamc/gomatter/mattertlv"
	"github.com/codegamc/gomatter/symbols"
)

func bootstrapCA(fabricID, adminUser uint64) {
	cm := gomat.NewFileCertManager(fabricID, gomat.FileCertManagerConfig{})
	cm.BootstrapCa()
	cm.Load()
	if err := cm.CreateUser(adminUser); err != nil {
		panic(err)
	}
}

func loadFabric(fabricID uint64) *gomat.Fabric {
	cm := gomat.NewFileCertManager(fabricID, gomat.FileCertManagerConfig{})
	cm.Load()
	return gomat.NewFabric(fabricID, cm)
}

func commission(fabricID, adminUser, deviceID uint64, deviceIP string, pin int) {
	fabric := loadFabric(fabricID)
	if err := gomat.Commission(context.Background(), fabric, net.ParseIP(deviceIP), pin, adminUser, deviceID); err != nil {
		panic(err)
	}
}

func sendOnCommand(secureChannel *gomat.SecureChannel) {
	onCommand := gomat.EncodeIMInvokeRequest(
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
	if response.ProtocolHeader.Opcode != gomat.InteractionOpcodeInvokeRsp {
		panic("unexpected message")
	}
	if status, err := gomat.ParseImInvokeResponse(&response.Tlv); err != nil || status != 0 {
		response.Tlv.Dump(0)
		panic("response was not OK")
	}
}

func sendColorCommand(secureChannel *gomat.SecureChannel) {
	var tlv mattertlv.TLVBuffer
	tlv.WriteUInt8(0, 100) // hue
	tlv.WriteUInt8(1, 200) // saturation
	tlv.WriteUInt8(2, 10)  // time
	colorCommand := gomat.EncodeIMInvokeRequest(
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
	if response.ProtocolHeader.Opcode != gomat.InteractionOpcodeInvokeRsp {
		panic("unexpected message")
	}
	if status, err := gomat.ParseImInvokeResponse(&response.Tlv); err != nil || status != 0 {
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
	secureChannel, err := gomat.ConnectDevice(context.Background(), net.ParseIP(deviceIP), 5540, fabric, deviceID, adminUser)
	if err != nil {
		panic(err)
	}
	defer secureChannel.Close()

	// send ON command
	sendOnCommand(secureChannel)

	// send set color command
	sendColorCommand(secureChannel)
}
