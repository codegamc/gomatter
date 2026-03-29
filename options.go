package gomatter

import "time"

// Option configures behavior of Commission and ConnectDevice.
type Option func(*channelOptions)

// SubscribeOption configures behavior of EncodeIMSubscribeRequest and EncodeIMSubscribeAttributeRequest.
type SubscribeOption func(*subscribeOptions)

type subscribeOptions struct {
	minInterval       uint16
	maxInterval       uint16
	keepSubscriptions bool
	fabricFiltered    bool
}

func defaultSubscribeOptions() subscribeOptions {
	return subscribeOptions{
		minInterval: defaultSubscribeMinInterval,
		maxInterval: defaultSubscribeMaxInterval,
	}
}

func applySubscribeOptions(opts []SubscribeOption) subscribeOptions {
	o := defaultSubscribeOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// WithMinInterval sets the minimum reporting interval in seconds. Defaults to 0.
func WithMinInterval(s uint16) SubscribeOption {
	return func(o *subscribeOptions) {
		o.minInterval = s
	}
}

// WithMaxInterval sets the maximum reporting interval in seconds. Defaults to 5.
func WithMaxInterval(s uint16) SubscribeOption {
	return func(o *subscribeOptions) {
		o.maxInterval = s
	}
}

// WithKeepSubscriptions controls whether existing subscriptions on the device are
// preserved when a new subscription is established. Defaults to false.
func WithKeepSubscriptions(keep bool) SubscribeOption {
	return func(o *subscribeOptions) {
		o.keepSubscriptions = keep
	}
}

// WithFabricFiltered limits attribute and event reports to data visible to the
// requesting fabric only. Defaults to false.
func WithFabricFiltered(filtered bool) SubscribeOption {
	return func(o *subscribeOptions) {
		o.fabricFiltered = filtered
	}
}

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
