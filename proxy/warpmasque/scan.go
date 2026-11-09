package warpmasque

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/rand/v2"
	gonet "net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	xerrors "github.com/xtls/xray-core/common/errors"
)

// Endpoint discovery, after the Android client's Aether core: try the address
// that worked last, then the configured one, then scan the consumer gateways for
// the ones that answer from this network ("balanced": collect a few, keep the
// fastest), and when nothing answers over UDP, do the same over TCP for h2.

// The consumer MASQUE gateways. Other addresses in the same /24s answer QUIC on
// 443 but are ordinary Cloudflare edges with a different key; the pinned
// endpoint key is what tells the gateways apart.
var (
	gatewayIPs   = []string{"162.159.198.1", "162.159.198.2", "162.159.199.1", "162.159.199.2"}
	gatewayPorts = []int{443, 500, 1701, 4443, 4500, 8095, 8443}

	// Over TCP the roles flip: almost every address in these /24s is an HTTP/2
	// MASQUE gateway with the pinned key, the h3 gateways above excepted.
	h2Prefixes = []string{"162.159.197", "162.159.198", "162.159.199"}
)

const h2Sample = 16 // h2 addresses tried per scan

const (
	scanWindow  = 2500 * time.Millisecond // how long a scan waits for answers
	scanKeep    = 3                       // balanced: stop after this many answers
	gatewayFile = "masque-gateway"        // in the working directory (the app group container on iOS)
)

// sniFallback replaces the WARP client's SNI, which Iran's firewall resets on
// sight; the gateways answer any name, and Aether defaults to this one.
const sniFallback = "www.cloudflare.com"

var errProbeDone = errors.New("probe done")

type scanHit struct {
	addr string
	rtt  time.Duration
}

// probeTLS clones base for a probe: it checks the server key against the pin,
// records when that happened, and aborts the handshake right there, so a probe
// never sends the client certificate or opens a tunnel.
func probeTLS(base *tls.Config, peerKey *ecdsa.PublicKey, matched func()) *tls.Config {
	cfg := base.Clone()
	cfg.VerifyConnection = nil
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) > 0 {
			if c, err := x509.ParseCertificate(raw[0]); err == nil {
				if k, ok := c.PublicKey.(*ecdsa.PublicKey); ok && k.Equal(peerKey) {
					matched()
				}
			}
		}
		return errProbeDone
	}
	return cfg
}

// scan dials every candidate at once and returns those whose key matched,
// fastest first.
func scan(ctx context.Context, candidates []string, dial func(ctx context.Context, addr string, matched func()) error) []scanHit {
	ctx, cancel := context.WithTimeout(ctx, scanWindow)
	defer cancel()
	var mu sync.Mutex
	var hits []scanHit
	var wg sync.WaitGroup
	for _, addr := range candidates {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			start := time.Now()
			_ = dial(ctx, addr, func() {
				mu.Lock()
				defer mu.Unlock()
				hits = append(hits, scanHit{addr, time.Since(start)})
				if len(hits) >= scanKeep {
					cancel()
				}
			})
		}(addr)
	}
	wg.Wait()
	sort.Slice(hits, func(i, j int) bool { return hits[i].rtt < hits[j].rtt })
	return hits
}

func gatewayCandidates(ports []int, skip map[string]bool) []string {
	var out []string
	for _, port := range ports {
		for _, ip := range gatewayIPs {
			addr := gonet.JoinHostPort(ip, strconv.Itoa(port))
			if !skip[addr] {
				out = append(out, addr)
			}
		}
	}
	return out
}

func (t *tunnel) scanH3(ctx context.Context, base *tls.Config, tried map[string]bool) []*gonet.UDPAddr {
	started := time.Now()
	hits := scan(ctx, gatewayCandidates(gatewayPorts, tried), func(ctx context.Context, addr string, matched func()) error {
		conn, err := quic.DialAddr(ctx, addr, probeTLS(t.attemptTLS(base, 0), t.peerKey, matched),
			&quic.Config{InitialPacketSize: 1200, HandshakeIdleTimeout: scanWindow})
		if conn != nil {
			conn.CloseWithError(0, "")
		}
		return err
	})
	xerrors.LogWarning(ctx, "masque[diag] h3 scan found ", len(hits), " gateway(s) in ", time.Since(started).Round(time.Millisecond), " ", hitList(hits))
	var out []*gonet.UDPAddr
	for _, h := range hits {
		if a, err := gonet.ResolveUDPAddr("udp", h.addr); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (t *tunnel) scanH2(ctx context.Context, base *tls.Config) []string {
	started := time.Now()
	candidates := h2Candidates(t.conf.Endpoint)
	hits := scan(ctx, candidates, func(ctx context.Context, addr string, matched func()) error {
		raw, err := (&gonet.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		defer raw.Close()
		cfg := probeTLS(t.attemptTLS(base, 0), t.peerKey, matched)
		cfg.NextProtos = []string{"h2"}
		return tls.Client(raw, cfg).HandshakeContext(ctx)
	})
	xerrors.LogWarning(ctx, "masque[diag] h2 scan found ", len(hits), " gateway(s) in ", time.Since(started).Round(time.Millisecond), " ", hitList(hits))
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.addr)
	}
	return out
}

func hitList(hits []scanHit) string {
	parts := make([]string, len(hits))
	for i, h := range hits {
		parts[i] = h.addr + "(" + h.rtt.Round(time.Millisecond).String() + ")"
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// rememberedGateway is the transport ("h3" or "h2") and address that last
// carried a tunnel, so the next start goes straight to it.
func rememberedGateway() (transport, addr string) {
	b, err := os.ReadFile(gatewayFile)
	if err != nil {
		return "", ""
	}
	transport, addr, _ = strings.Cut(strings.TrimSpace(string(b)), " ")
	if transport != "h3" && transport != "h2" {
		return "", ""
	}
	return transport, addr
}

func rememberGateway(transport, addr string) {
	_ = os.WriteFile(gatewayFile, []byte(transport+" "+addr+"\n"), 0o600)
}

// h2Candidates is the configured address on TCP 443 followed by a random sample
// of the h2 gateways.
func h2Candidates(configured string) []string {
	out := []string{}
	seen := map[string]bool{}
	if host, _, err := gonet.SplitHostPort(configured); err == nil {
		a := gonet.JoinHostPort(host, "443")
		out, seen[a] = append(out, a), true
	}
	for len(out) < h2Sample+1 {
		a := h2Prefixes[rand.IntN(len(h2Prefixes))] + "." + strconv.Itoa(3+rand.IntN(252)) + ":443"
		if !seen[a] {
			out, seen[a] = append(out, a), true
		}
	}
	return out
}
