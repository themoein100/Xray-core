package tun

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func TestUDPCloseAllReleasesParkedFlows(t *testing.T) {
	done := make(chan struct{}, 2)
	h := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {
		// Mirror the real handler: park reading until the flow is closed.
		for {
			if _, err := conn.(*udpConn).ReadMultiBuffer(); err != nil {
				break
			}
		}
		conn.Close()
		done <- struct{}{}
	}, func(data []byte, src net.Destination, dst net.Destination) error { return nil })

	dst := net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), 53)
	h.HandlePacket(net.UDPDestination(net.IPAddress([]byte{10, 0, 0, 1}), 50001), dst, []byte{1})
	h.HandlePacket(net.UDPDestination(net.IPAddress([]byte{10, 0, 0, 1}), 50002), dst, []byte{1})

	h.closeAll()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("flow goroutine still parked after closeAll")
		}
	}

	// No new flow after shutdown.
	h.HandlePacket(net.UDPDestination(net.IPAddress([]byte{10, 0, 0, 1}), 50003), dst, []byte{1})
	h.RLock()
	n := len(h.udpConns)
	h.RUnlock()
	if n != 0 {
		t.Fatalf("flow accepted after closeAll: %d", n)
	}
}
