package dns

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestSessionIdleTimeout(t *testing.T) {
	cases := []struct {
		network net.Network
		idle    time.Duration
		want    time.Duration
	}{
		{net.Network_UDP, 300 * time.Second, udpDNSSessionIdle},
		{net.Network_UDP, 0, udpDNSSessionIdle},
		{net.Network_UDP, 2 * time.Second, 2 * time.Second},
		{net.Network_TCP, 300 * time.Second, 300 * time.Second},
	}
	for _, c := range cases {
		if got := sessionIdleTimeout(c.network, c.idle); got != c.want {
			t.Errorf("sessionIdleTimeout(%v, %v) = %v, want %v", c.network, c.idle, got, c.want)
		}
	}
}
