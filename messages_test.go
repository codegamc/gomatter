package gomat

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codegamc/gomatter/mattertlv"
)

func decodeInteractionMessage(t *testing.T, encoded []byte) (ProtocolMessageHeader, mattertlv.TlvItem) {
	t.Helper()

	buf := bytes.NewBuffer(encoded)
	var header ProtocolMessageHeader
	header.Decode(buf)
	return header, mattertlv.Decode(buf.Bytes())
}

func assertSubscribeEnvelope(t *testing.T, decoded mattertlv.TlvItem) {
	t.Helper()

	keep := decoded.GetItemRec([]int{0})
	if keep == nil {
		t.Fatal("keep flag missing")
	}
	if keep.GetBool() {
		t.Fatal("unexpected keep flag: true")
	}

	fabricFiltered := decoded.GetItemRec([]int{7})
	if fabricFiltered == nil {
		t.Fatal("fabric filtered flag missing")
	}
	if fabricFiltered.GetBool() {
		t.Fatal("unexpected fabric filtered flag: true")
	}

	imRevision, err := decoded.GetIntRec([]int{255})
	if err != nil {
		t.Fatalf("interaction model revision missing: %v", err)
	}
	if imRevision != 10 {
		t.Fatalf("unexpected interaction model revision: %d", imRevision)
	}
}

func assertSubscribeDefaults(t *testing.T, decoded mattertlv.TlvItem) {
	t.Helper()
	assertSubscribeEnvelope(t, decoded)
	assertSubscribeIntervals(t, decoded, 0, 5)
}

func assertSubscribeIntervals(t *testing.T, decoded mattertlv.TlvItem, wantMin uint64, wantMax uint64) {
	t.Helper()

	minInterval, err := decoded.GetIntRec([]int{1})
	if err != nil {
		t.Fatalf("min interval missing: %v", err)
	}
	if minInterval != wantMin {
		t.Fatalf("unexpected min interval: %d", minInterval)
	}

	maxInterval, err := decoded.GetIntRec([]int{2})
	if err != nil {
		t.Fatalf("max interval missing: %v", err)
	}
	if maxInterval != wantMax {
		t.Fatalf("unexpected max interval: %d", maxInterval)
	}
}

func TestEncodeIMSubscribeRequestRegression(t *testing.T) {
	encoded := EncodeIMSubscribeRequest(1, 0x101, 1)
	if got := hex.EncodeToString(encoded); got != "05030000010015280025010000250205003604172501010026020101000026030100000029041818280724ff0a18" {
		t.Fatalf("unexpected encoding: %s", got)
	}

	header, decoded := decodeInteractionMessage(t, encoded)
	if header.Opcode != INTERACTION_OPCODE_SUBSC_REQ {
		t.Fatalf("unexpected opcode: 0x%x", header.Opcode)
	}
	if header.ProtocolId != ProtocolIdInteraction {
		t.Fatalf("unexpected protocol id: %d", header.ProtocolId)
	}

	assertSubscribeDefaults(t, decoded)

	endpoint, err := decoded.GetIntRec([]int{4, 0, 1})
	if err != nil || endpoint != 1 {
		t.Fatalf("unexpected event endpoint: %d err=%v", endpoint, err)
	}
	cluster, err := decoded.GetIntRec([]int{4, 0, 2})
	if err != nil || cluster != 0x101 {
		t.Fatalf("unexpected event cluster: %d err=%v", cluster, err)
	}
	event, err := decoded.GetIntRec([]int{4, 0, 3})
	if err != nil || event != 1 {
		t.Fatalf("unexpected event id: %d err=%v", event, err)
	}
	urgent := decoded.GetItemRec([]int{4, 0, 4})
	if urgent == nil {
		t.Fatal("urgent flag missing")
	}
	if !urgent.GetBool() {
		t.Fatal("unexpected urgent flag: false")
	}
}

func TestEncodeIMSubscribeAttributeRequest(t *testing.T) {
	encoded := EncodeIMSubscribeAttributeRequest(1, 0x6, 0)

	header, decoded := decodeInteractionMessage(t, encoded)
	if header.Opcode != INTERACTION_OPCODE_SUBSC_REQ {
		t.Fatalf("unexpected opcode: 0x%x", header.Opcode)
	}
	if header.ProtocolId != ProtocolIdInteraction {
		t.Fatalf("unexpected protocol id: %d", header.ProtocolId)
	}

	assertSubscribeDefaults(t, decoded)

	endpoint, err := decoded.GetIntRec([]int{3, 0, 2})
	if err != nil || endpoint != 1 {
		t.Fatalf("unexpected attribute endpoint: %d err=%v", endpoint, err)
	}
	cluster, err := decoded.GetIntRec([]int{3, 0, 3})
	if err != nil || cluster != 0x6 {
		t.Fatalf("unexpected attribute cluster: %d err=%v", cluster, err)
	}
	attr, err := decoded.GetIntRec([]int{3, 0, 4})
	if err != nil || attr != 0 {
		t.Fatalf("unexpected attribute id: %d err=%v", attr, err)
	}
}

func TestEncodeIMSubscribeAttributeRequestWithIntervals(t *testing.T) {
	encoded := EncodeIMSubscribeAttributeRequestWithIntervals(1, 0x6, 0, 2, 9)

	header, decoded := decodeInteractionMessage(t, encoded)
	if header.Opcode != INTERACTION_OPCODE_SUBSC_REQ {
		t.Fatalf("unexpected opcode: 0x%x", header.Opcode)
	}
	if header.ProtocolId != ProtocolIdInteraction {
		t.Fatalf("unexpected protocol id: %d", header.ProtocolId)
	}

	assertSubscribeEnvelope(t, decoded)
	assertSubscribeIntervals(t, decoded, 2, 9)
}
