package gomatter

import "time"

// Option configures behavior of Commission and ConnectDevice.
type Option func(*channelOptions)

type channelOptions struct {
	localPort      int
	remotePort     int
	receiveTimeout time.Duration
}

func defaultChannelOptions() channelOptions {
	return channelOptions{
		localPort:      0,
		remotePort:     5540,
		receiveTimeout: defaultReceiveTimeout,
	}
}

func applyOptions(opts []Option) channelOptions {
	o := defaultChannelOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// WithLocalPort sets the local UDP port. Defaults to 0 (OS-assigned).
func WithLocalPort(port int) Option {
	return func(o *channelOptions) {
		o.localPort = port
	}
}

// WithRemotePort sets the remote UDP port. Defaults to 5540 (standard Matter port).
// Applies to Commission only; ConnectDevice takes the remote port as an explicit argument.
func WithRemotePort(port int) Option {
	return func(o *channelOptions) {
		o.remotePort = port
	}
}

// WithReceiveTimeout sets the per-receive deadline. Defaults to 3 seconds. Use 0 for no timeout.
func WithReceiveTimeout(d time.Duration) Option {
	return func(o *channelOptions) {
		o.receiveTimeout = d
	}
}
