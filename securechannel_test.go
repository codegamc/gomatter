package gomatter

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

var errFakeRead = errors.New("fake read error")

type fakePacketConn struct {
	deadline time.Time
	reads    int
}

func (f *fakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	f.reads++
	return 0, nil, errFakeRead
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (f *fakePacketConn) Close() error {
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (f *fakePacketConn) SetDeadline(t time.Time) error {
	f.deadline = t
	return nil
}

func (f *fakePacketConn) SetReadDeadline(t time.Time) error {
	f.deadline = t
	return nil
}

func (f *fakePacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestReceiveUsesConfiguredTimeout(t *testing.T) {
	fakeConn := &fakePacketConn{}
	sc := newSecureChannel(&udpChannel{Udp: fakeConn})
	sc.SetReceiveTimeout(5 * time.Second)

	_, err := sc.Receive(context.Background())
	if !errors.Is(err, errFakeRead) {
		t.Fatalf("unexpected receive error: %v", err)
	}
	if fakeConn.deadline.IsZero() {
		t.Fatal("expected receive deadline to be set")
	}

	remaining := time.Until(fakeConn.deadline)
	if remaining <= 0 || remaining > 5*time.Second+500*time.Millisecond {
		t.Fatalf("unexpected deadline offset: %s", remaining)
	}
}

func TestReceiveUsesEarlierContextDeadline(t *testing.T) {
	fakeConn := &fakePacketConn{}
	sc := newSecureChannel(&udpChannel{Udp: fakeConn})
	sc.SetReceiveTimeout(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := sc.Receive(ctx)
	if !errors.Is(err, errFakeRead) {
		t.Fatalf("unexpected receive error: %v", err)
	}

	remaining := time.Until(fakeConn.deadline)
	if remaining <= 0 || remaining > time.Second+500*time.Millisecond {
		t.Fatalf("expected context deadline to win, got %s", remaining)
	}
}

func TestReceiveCanceledContextReturnsContextError(t *testing.T) {
	fakeConn := &fakePacketConn{}
	sc := newSecureChannel(&udpChannel{Udp: fakeConn})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sc.Receive(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context error, got %v", err)
	}
	if fakeConn.reads != 0 {
		t.Fatalf("expected receive to stop before reading, got %d reads", fakeConn.reads)
	}
}

func TestReceiveBlockingClearsDeadline(t *testing.T) {
	fakeConn := &fakePacketConn{}
	sc := newSecureChannel(&udpChannel{Udp: fakeConn})

	_, err := sc.ReceiveBlocking()
	if !errors.Is(err, errFakeRead) {
		t.Fatalf("unexpected receive error: %v", err)
	}
	if !fakeConn.deadline.IsZero() {
		t.Fatalf("expected blocking receive to clear deadline, got %v", fakeConn.deadline)
	}
}
