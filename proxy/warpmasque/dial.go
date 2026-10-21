package warpmasque

import (
	"context"
	"crypto/tls"
	"math/rand/v2"
	gonet "net"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/net"
)

// Outbound plumbing shared by both transports: where the endpoint socket comes
// from (the system, or Xray's dialer when the tunnel is chained inside another
// outbound), ClientHello fragmentation, and TLS key-share groups.

// dialTCP opens the h2 transport's TCP connection.
func (t *tunnel) dialTCP(ctx context.Context) (gonet.Conn, error) {
	if t.conf.Chain && t.dialer != nil {
		dest, err := net.ParseDestination("tcp:" + t.conf.Endpoint)
		if err != nil {
			return nil, err
		}
		return t.dialer.Dial(context.Background(), dest)
	}
	return (&gonet.Dialer{}).DialContext(ctx, "tcp", t.conf.Endpoint)
}

// dialUDP opens the h3 transport's socket through Xray's dialer. The result is
// a connected flow, wrapped so quic-go can use it as a PacketConn.
func (t *tunnel) dialUDP() (gonet.PacketConn, gonet.Addr, error) {
	dest, err := net.ParseDestination("udp:" + t.conf.Endpoint)
	if err != nil {
		return nil, nil, err
	}
	conn, err := t.dialer.Dial(context.Background(), dest)
	if err != nil {
		return nil, nil, err
	}
	remote, err := gonet.ResolveUDPAddr("udp", t.conf.Endpoint)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return &flowPacketConn{Conn: conn, remote: remote}, remote, nil
}

// flowPacketConn adapts a connected flow (one peer) to net.PacketConn.
type flowPacketConn struct {
	gonet.Conn
	remote gonet.Addr
}

func (c *flowPacketConn) ReadFrom(b []byte) (int, gonet.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, c.remote, err
}

func (c *flowPacketConn) WriteTo(b []byte, _ gonet.Addr) (int, error) {
	return c.Conn.Write(b)
}

// fragmentConn splits the first write — the TLS ClientHello — into small chunks
// with short pauses, so middleboxes that read the SNI from one segment miss it.
type fragmentConn struct {
	gonet.Conn
	done       bool
	minSize    int
	maxSize    int
	minDelayMs int
	maxDelayMs int
}

func newFragmentConn(c gonet.Conn, size, delay string) *fragmentConn {
	minSize, maxSize := parseRange(size, 8, 16)
	minDelay, maxDelay := parseRange(delay, 2, 10)
	if minSize < 1 {
		minSize = 1
	}
	return &fragmentConn{Conn: c, minSize: minSize, maxSize: maxSize, minDelayMs: minDelay, maxDelayMs: maxDelay}
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.done = true
	written := 0
	for written < len(b) {
		n := between(c.minSize, c.maxSize)
		if written+n > len(b) {
			n = len(b) - written
		}
		m, err := c.Conn.Write(b[written : written+n])
		written += m
		if err != nil {
			return written, err
		}
		if written < len(b) {
			time.Sleep(time.Duration(between(c.minDelayMs, c.maxDelayMs)) * time.Millisecond)
		}
	}
	return written, nil
}

// parseRange reads "n" or "a-b"; anything unreadable yields the defaults.
func parseRange(s string, defMin, defMax int) (int, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return defMin, defMax
	}
	lo, hi, found := strings.Cut(s, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil || a < 0 {
		return defMin, defMax
	}
	if !found {
		return a, a
	}
	b, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil || b < a {
		return defMin, defMax
	}
	return a, b
}

func between(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + rand.IntN(hi-lo+1)
}

// applyTLSGroups sets the key-share preference from a list such as
// "P-256:X25519:P-384". Unknown names are skipped; an empty result keeps Go's default.
func applyTLSGroups(cfg *tls.Config, groups string) {
	var curves []tls.CurveID
	for _, name := range strings.FieldsFunc(groups, func(r rune) bool { return r == ':' || r == ',' || r == ' ' }) {
		switch strings.ToLower(name) {
		case "p-256", "p256", "secp256r1", "prime256v1":
			curves = append(curves, tls.CurveP256)
		case "p-384", "p384", "secp384r1":
			curves = append(curves, tls.CurveP384)
		case "p-521", "p521", "secp521r1":
			curves = append(curves, tls.CurveP521)
		case "x25519":
			curves = append(curves, tls.X25519)
		case "x25519mlkem768", "x25519-mlkem768", "mlkem":
			curves = append(curves, tls.X25519MLKEM768)
		}
	}
	if len(curves) > 0 {
		cfg.CurvePreferences = curves
	}
}
