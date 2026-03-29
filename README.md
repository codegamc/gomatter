# gomatter
Simple Matter protocol library for Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/codegamc/gomatter.svg)](https://pkg.go.dev/github.com/codegamc/gomatter)
![go build](https://github.com/codegamc/gomatter/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/codegamc/gomatter)](https://goreportcard.com/report/github.com/codegamc/gomatter)

### goal of project
The goal is to create golang library and supporting tools to access matter devices.

### status of project
- it can
  - commission devices
  - send commands to devices
  - read attributes from devices
  - subscribe and receive events or attributes
  - decode onboarding info (qr text, manual pair code)
  - discover commissionable devices
  - discover commissioned devices
  - open commissioning window


#### tested devices
- tested against virtual devices which are part of reference implementation https://github.com/project-chip/connectedhomeip
- tested with yeelight cube
- tested with Tapo Devices:
  - VID: 5010, PID: 261 (Tapo P110M)

### general info
- it is best to understand matter to use this, but here is most important info:
  - device access is managed using certificates
  - easiest way how to talk to device is to have signed certificate of device admin user (alternative is setup ACLs and use non-admin user)
  - certificates are signed by CA
  - during commissioning procedure root CA certificate is pushed to device together with id of device admin user
  - root CA certificate is something you need to create once and store. loosing CA keys usually means that you will have to commission devices again
  - to talk to device you have to commission it first
    - to commission device you usually need its pin/passcode and device be in state open for commissioning
    - device gets into commissioning window open state often by "factory reset"
    - when device is commissioned - connected to some fabric, it can be commissioned into other fabrics using api, where existing admin user sets device to be open for additional commissioning. During that device can be connected to additional fabric(s) - additional root CA installed and additional admin user configured

### how to use test application
- compile
```
git clone git@github.com:codegamc/gomatter.git
cd gomatter
go build -o gomatter demo/main.go
```

- create directory to hold keys and certificates `mkdir pem`
- generate CA key and certificate using `./gomatter ca-bootstrap`
- generate controller key and certificate using `./gomatter ca-createuser 100`
  - 100 is example node-id of controller
- find device IP
  - discover command can be used to discover matter devices and their ip address `./gomatter discover commissionable -d`
- find device commissioning passcode/pin
  - device may show it
  - it can be extracted from QR code. use decode-qr to extract passcode from text representation of QR code `./gomatter decode-qr MT:-24J0AFN00SIQ663000`
  - it can be extracted from manual pairing code. use command decode-mc to extract passcode from manual pairing code `./gomatter decode-mc 35792000079`
- perform commissioning of device. This authenticates using passcode, uploads CA certificate to device, signs and uploads device's own certificate and sets admin user id.
  - required for commissioning:
    - ip address of device
    - device commissioning passcode/pin
    - ca key and certificate
    - controller node key and certificate
  - example: `./gomatter commission --ip 192.168.5.178 --pin 123456 --controller-id 100 --device-id 500`
- light on!
  `./gomatter cmd on --ip 192.168.5.178 --controller-id 100 --device-id 500`
- set color hue=150 saturation=200 transition_time=10
  `./gomatter cmd color --ip 192.168.5.220 --controller-id 100 --device-id 500 150 200 10`
- subscribe to a Matter event
  `./gomatter cmd subscribe --ip 192.168.5.178 --controller-id 100 --device-id 500 1 0x101 1`
- subscribe to an attribute report
  `./gomatter cmd subscribe-attr --ip 192.168.5.178 --controller-id 100 --device-id 500 1 0x6 0`
  - subscription commands now default to low-latency intervals: `--min-interval=0 --max-interval=5`
  - override them when needed, for example: `./gomatter cmd subscribe-attr --ip 192.168.5.178 --controller-id 100 --device-id 500 --min-interval 0 --max-interval 1 1 0x6 0`


### how to use api
#### Example applications
- [Simple Example application](examples/basic/basic-main.go) - bootstrap ca, commission, send commands to device
- [Demo application](demo/main.go)

For low-level subscriptions, use `EncodeIMSubscribeRequest` for event subscriptions and `EncodeIMSubscribeAttributeRequest` for attribute subscriptions.
These now default to `minInterval=0` and `maxInterval=5` for lower-latency reporting.
Use `EncodeIMSubscribeRequestWithIntervals` or `EncodeIMSubscribeAttributeRequestWithIntervals` to override the intervals explicitly.

#### commission device using api
create ca with root certificate, create admin user, then commission device:
```
package main

import (
  "context"
  "net"

  "github.com/codegamc/gomatter"
)


func main() {
  var fabricID uint64 = 0x100
  var adminUser uint64 = 5
  var deviceID uint64 = 10
  deviceIP := "192.168.5.178"
  pin := 123456

  cm := gomatter.NewFileCertManager(fabricID, gomatter.FileCertManagerConfig{})
  cm.BootstrapCa()
  cm.Load()
  cm.CreateUser(adminUser)
  fabric := gomatter.NewFabric(fabricID, cm)
  gomatter.Commission(context.Background(), fabric, net.ParseIP(deviceIP), pin, adminUser, deviceID)
}
```

#### send ON command to commissioned device using api
```
package main

import (
  "context"
  "net"

  "github.com/codegamc/gomatter"
)


func main() {
  var fabricID uint64 = 0x100
  var adminUser uint64 = 5
  var deviceID uint64 = 10
  deviceIP := "192.168.5.178"

  cm := gomatter.NewFileCertManager(fabricID, gomatter.FileCertManagerConfig{})
  cm.Load()
  fabric := gomatter.NewFabric(fabricID, cm)

  secureChannel, err := gomatter.ConnectDevice(context.Background(), net.ParseIP(deviceIP), 5540, fabric, deviceID, adminUser)
  if err != nil {
    panic(err)
  }
  defer secureChannel.Close()

  on_command := gomatter.EncodeInvokeCommand(1,        // endpoint
                                          6,        // api cluster (on/off)
                                          1,        // on command
                                          []byte{}, // no extra data
                                          )
  secureChannel.Send(on_command)
  resp, err := secureChannel.Receive(context.Background())
  if err != nil {
    panic(err)
  }
  resp.Tlv.Dump(0)
}
```

#### discover IP address of previously commissioned device using api
Device exposes its info using mdns under identifier [compressed-fabric-id]-[device-id].
For this reason to discover commissioned device fabric info is required.
```
package main

import (
  "encoding/hex"
  "fmt"
  "strings"

  "github.com/codegamc/gomatter"
  "github.com/codegamc/gomatter/discover"
)



func main() {
  var fabricID uint64 = 0x100
  var deviceID uint64 = 10


  cm := gomatter.NewFileCertManager(fabricID, gomatter.FileCertManagerConfig{})
  cm.Load()
  fabric := gomatter.NewFabric(fabricID, cm)

  identifier := fmt.Sprintf("%s-%016X", hex.EncodeToString(fabric.CompressedFabric()), deviceID)
  identifier = strings.ToUpper(identifier)
  identifier = identifier + "._matter._tcp.local."
  fmt.Printf("%s\n", identifier)
  devices := discover.DiscoverCommissioned("", true, identifier)
  for _, d := range devices {
    fmt.Printf("host:%s ip:%v\n", d.Host, d.Addrs)
  }
}
```

#### extract pairing passcode from QR code and manual pairing code
Following example shows how to extract passcode from textual representation of QR code or from manual pairing code.
Manual pairing code can have dash characters at any position(they are discarded)
```
package main

import (
	"fmt"

	"github.com/codegamc/gomatter/onboarding_payload"
)


func main() {
	setup_qr_code := "MT:-24J0AFN00SIQ663000"
	qr_decoded := onboarding_payload.DecodeQrText(setup_qr_code)
	fmt.Printf("passcode: %d\n", qr_decoded.Passcode)


	manual_pair_code := "357-920-000-79"
	code_decoded := onboarding_payload.DecodeManualPairingCode(manual_pair_code)
	fmt.Printf("passcode: %d\n", code_decoded.Passcode)
}

```

#### Set color of light to specific hue color
```
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/codegamc/gomatter"
	"github.com/codegamc/gomatter/mattertlv"
)


func main() {
	var fabricID uint64 = 0x100
	var adminUser uint64 = 5
	var deviceID uint64 = 10
	deviceIP := "192.168.5.178"

	cm := gomatter.NewFileCertManager(fabricID, gomatter.FileCertManagerConfig{})
	cm.Load()
	fabric := gomatter.NewFabric(fabricID, cm)


	secureChannel, err := gomatter.ConnectDevice(context.Background(), net.ParseIP(deviceIP), 5540, fabric, deviceID, adminUser)
	if err != nil {
		panic(err)
	}
	defer secureChannel.Close()

	var tlv mattertlv.TLVBuffer
	tlv.WriteUInt8(0, byte(hue))        // hue
	tlv.WriteUInt8(1, byte(saturation)) // saturation
	tlv.WriteUInt8(2, byte(time))       // time
	to_send := gomatter.EncodeInvokeCommand(1, 0x300, 6, tlv.Bytes())
	secureChannel.Send(to_send)

	resp, err := secureChannel.Receive(context.Background())
	if err != nil {
		panic(err)
	}
	status, err := resp.Tlv.GetIntRec([]int{1,0,1,1,0})
	if err != nil {
		panic(err)
	}
	fmt.Printf("result status: %d\n", status)
}
```


#### certificate manager
NewFabric function accepts certificate manager object as input parameter. Certificate manager must implement interface CertificateManager and user can supply own implementation. Supplied CertManager created by `NewFileCertManager` stores all data in `.pem` files under the default `pem` directory, and `FileCertManagerConfig.Path` can be used to store them somewhere else.
