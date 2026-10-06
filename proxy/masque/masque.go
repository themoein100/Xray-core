// Package masque is a Cloudflare WARP client over MASQUE (HTTP/3 CONNECT-IP).
//
// The tunnel is a QUIC connection to a WARP MASQUE endpoint that carries raw IP
// packets. A userspace network stack sits on top of it and every Xray request is
// dialled through that stack, the same way the WireGuard outbound works.
package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	gonet "net"
	"net/netip"
	"sync"
	"time"

	"github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

const (
	defaultSNI      = "consumer-masque.cloudflareclient.com"
	connectURI      = "https://cloudflareaccess.com"
	maxInnerMTU     = 1150
	keepalive       = 30 * time.Second
	reconnectDelay  = time.Second
	firstConnectMax = 10 * time.Second
	idleLinger      = 90 * time.Second
	dnsTimeout      = 4 * time.Second
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

type Handler struct {
	conf          *Config
	policyManager policy.Manager

	mu     sync.Mutex
	closed bool
	tunnel *tunnel
}

func New(ctx context.Context, conf *Config) (*Handler, error) {
	v := core.MustFromContext(ctx)
	return &Handler{
		conf:          conf,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

// Close implements common.Closable.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	if h.tunnel != nil {
		release(h.tunnel)
		h.tunnel = nil
	}
	return nil
}

// start attaches the handler to its tunnel on first use and waits for it to be up.
func (h *Handler) start(ctx context.Context) (*tunnel, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, xerrors.New("masque: closed")
	}
	if h.tunnel == nil {
		t, err := acquire(h.conf)
		if err != nil {
			h.mu.Unlock()
			return nil, err
		}
		h.tunnel = t
	}
	t := h.tunnel
	h.mu.Unlock()
	return t, t.wait(ctx)
}

// Outbounds with the same account and endpoint share one tunnel. The tunnel
// extension clones the proxy outbound under new tags (Telegram, ad media); each
// clone with its own QUIC connection and network stack would cost memory the
// extension does not have and register the same device several times over.
var (
	tunnelsMu sync.Mutex
	tunnels   = map[string]*tunnel{}
)

type tunnel struct {
	key       string
	refs      int
	idleTimer *time.Timer
	conf      *Config

	mu      sync.Mutex
	cancel  context.CancelFunc
	tunDev  tun.Device
	tnet    *netstack.Net
	ready   chan struct{} // closed once the first connection is up
	lastErr error
}

func acquire(conf *Config) (*tunnel, error) {
	key := conf.PrivateKey + "|" + conf.Endpoint + "|" + conf.Sni
	tunnelsMu.Lock()
	defer tunnelsMu.Unlock()
	if t, ok := tunnels[key]; ok {
		if t.idleTimer != nil {
			t.idleTimer.Stop()
			t.idleTimer = nil
		}
		t.refs++
		return t, nil
	}
	t := &tunnel{key: key, refs: 1, conf: conf, ready: make(chan struct{})}
	if err := t.launch(); err != nil {
		return nil, err
	}
	tunnels[key] = t
	return t, nil
}

// release keeps an unused tunnel open for idleLinger before closing it. Pings
// run in short-lived Xray instances and a connect follows a ping within seconds;
// tearing the tunnel down with each instance made every one of them pay a fresh
// QUIC + CONNECT-IP handshake, which from a slow network did not fit inside a
// ping's deadline at all.
func release(t *tunnel) {
	tunnelsMu.Lock()
	defer tunnelsMu.Unlock()
	t.refs--
	if t.refs > 0 {
		return
	}
	t.idleTimer = time.AfterFunc(idleLinger, func() {
		tunnelsMu.Lock()
		defer tunnelsMu.Unlock()
		if t.refs > 0 || tunnels[t.key] != t {
			return
		}
		delete(tunnels, t.key)
		t.cancel()
		t.tunDev.Close()
	})
}

// wait blocks (bounded) until the first connection is up, so the first request
// does not race an unconnected stack.
func (t *tunnel) wait(ctx context.Context) error {
	select {
	case <-t.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(firstConnectMax):
		t.mu.Lock()
		err := t.lastErr
		t.mu.Unlock()
		if err == nil {
			err = errors.New("no answer from endpoint")
		}
		return xerrors.New("masque: tunnel not established").Base(err)
	}
}

func (t *tunnel) launch() error {
	privKey, err := parsePrivateKey(t.conf.PrivateKey)
	if err != nil {
		return xerrors.New("masque: private key").Base(err)
	}
	peerKey, err := parsePublicKey(t.conf.EndpointPublicKey)
	if err != nil {
		return xerrors.New("masque: endpoint public key").Base(err)
	}
	endpoint, err := gonet.ResolveUDPAddr("udp", t.conf.Endpoint)
	if err != nil {
		return xerrors.New("masque: endpoint ", t.conf.Endpoint).Base(err)
	}

	var local []netip.Addr
	for _, a := range t.conf.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			local = append(local, p.Addr())
		} else if ip, err := netip.ParseAddr(a); err == nil {
			local = append(local, ip)
		}
	}
	if len(local) == 0 {
		return xerrors.New("masque: no tunnel address")
	}
	var dns []netip.Addr
	for _, d := range t.conf.Dns {
		if ip, err := netip.ParseAddr(d); err == nil {
			dns = append(dns, ip)
		}
	}
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")}
	}
	// Every inner IP packet travels in one QUIC DATAGRAM, and those are capped by
	// the QUIC packet size, which starts at 1200 bytes (see maintain). A bigger
	// inner packet is dropped without an error the stack can see: a TCP connection
	// then stalls on its first full-size segment — a TLS ClientHello with a
	// post-quantum key share is one. Keep the stack below what fits.
	mtu := int(t.conf.Mtu)
	if mtu <= 0 || mtu > maxInnerMTU {
		mtu = maxInnerMTU
	}

	cert, err := selfSignedCert(privKey)
	if err != nil {
		return xerrors.New("masque: certificate").Base(err)
	}
	sni := t.conf.Sni
	if sni == "" {
		sni = defaultSNI
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerKey, cert, sni)
	if err != nil {
		return xerrors.New("masque: tls").Base(err)
	}

	tunDev, tnet, err := netstack.CreateNetTUN(local, dns, mtu)
	if err != nil {
		return xerrors.New("masque: netstack").Base(err)
	}
	t.tunDev, t.tnet = tunDev, tnet

	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	go t.maintain(ctx, tlsConfig, endpoint, api.NewNetstackAdapter(tunDev), mtu)
	return nil
}

// maintain keeps one MASQUE connection alive and pumps packets both ways,
// reconnecting on failure until the handler is closed.
func (t *tunnel) maintain(ctx context.Context, tlsConfig *tls.Config, endpoint *gonet.UDPAddr, dev api.TunnelDevice, mtu int) {
	signalled := false
	for ctx.Err() == nil {
		// Start at the QUIC minimum: a full-size Initial is silently dropped on paths
		// with a smaller MTU (tunnels, many mobile networks) and the handshake never
		// completes. Path-MTU discovery stays on, so packets still grow afterwards.
		quicConfig := &quic.Config{EnableDatagrams: true, KeepAlivePeriod: keepalive, InitialPacketSize: 1200}
		udpConn, tr, ipConn, rsp, err := api.ConnectTunnel(ctx, tlsConfig, quicConfig, connectURI, endpoint)
		if err == nil && rsp != nil && rsp.StatusCode != 200 {
			err = xerrors.New("endpoint answered ", rsp.Status)
		}
		if err != nil {
			if ipConn != nil {
				ipConn.Close()
			}
			if udpConn != nil {
				udpConn.Close()
			}
			if tr != nil {
				tr.Close()
			}
			t.mu.Lock()
			t.lastErr = err
			t.mu.Unlock()
			xerrors.LogInfo(ctx, "masque: connect failed: ", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(reconnectDelay):
			}
			continue
		}
		if !signalled {
			close(t.ready)
			signalled = true
		}

		errCh := make(chan error, 2)
		go func() {
			b := make([]byte, mtu+64)
			for {
				n, err := dev.ReadPacket(b)
				if err != nil {
					errCh <- err
					return
				}
				icmp, err := ipConn.WritePacket(b[:n])
				if err != nil {
					if errors.As(err, new(*connectip.CloseError)) {
						errCh <- err
						return
					}
					continue
				}
				if len(icmp) > 0 {
					_ = dev.WritePacket(icmp)
				}
			}
		}()
		go func() {
			b := make([]byte, mtu+64)
			for {
				n, err := ipConn.ReadPacket(b, true)
				if err != nil {
					if errors.As(err, new(*connectip.CloseError)) {
						errCh <- err
						return
					}
					continue
				}
				if err := dev.WritePacket(b[:n]); err != nil {
					errCh <- err
					return
				}
			}
		}()

		select {
		case <-ctx.Done():
		case err := <-errCh:
			xerrors.LogInfo(ctx, "masque: tunnel lost: ", err)
		}
		ipConn.Close()
		udpConn.Close()
		tr.Close()
	}
}

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return xerrors.New("target not specified")
	}
	ob.Name = "masque"
	ob.CanSpliceCopy = 3

	t, err := h.start(ctx)
	if err != nil {
		return err
	}

	var addr netip.Addr
	if ob.Target.Address.Family().IsDomain() {
		addr, err = t.resolve(ctx, ob.Target.Address.Domain())
		if err != nil {
			return xerrors.New("masque: failed to resolve ", ob.Target.Address.Domain()).Base(err)
		}
	} else {
		addr, _ = netip.AddrFromSlice(ob.Target.Address.IP())
		addr = addr.Unmap()
	}
	addrPort := netip.AddrPortFrom(addr, ob.Target.Port.Value())

	sessionPolicy := h.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	var conn gonet.Conn
	switch ob.Target.Network {
	case net.Network_TCP:
		dialCtx := ctx
		if sessionPolicy.Timeouts.Handshake != 0 {
			var c context.CancelFunc
			dialCtx, c = context.WithTimeout(ctx, sessionPolicy.Timeouts.Handshake)
			defer c()
		}
		conn, err = t.tnet.DialContextTCPAddrPort(dialCtx, addrPort)
	case net.Network_UDP:
		conn, err = t.tnet.DialUDPAddrPort(netip.AddrPort{}, addrPort)
	default:
		return xerrors.New("masque: unsupported network ", ob.Target.Network)
	}
	if err != nil {
		return xerrors.New("masque: dial ", addrPort).Base(err)
	}
	defer conn.Close()

	requestFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}
	responseFunc := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}
	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return xerrors.New("connection ends").Base(err)
	}
	return nil
}

// resolve looks the name up inside the tunnel and prefers IPv4, which every WARP
// exit carries; IPv6 egress is not guaranteed on every account and path.
func (t *tunnel) resolve(ctx context.Context, host string) (netip.Addr, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	ips, err := t.tnet.LookupContextHost(lookupCtx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	var v6 netip.Addr
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if ip.Is4() || ip.Is4In6() {
			return ip.Unmap(), nil
		}
		if !v6.IsValid() {
			v6 = ip
		}
	}
	if v6.IsValid() {
		return v6, nil
	}
	return netip.Addr{}, errors.New("no address")
}

func parsePrivateKey(b64 string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	return ec, nil
}

func parsePublicKey(s string) (*ecdsa.PublicKey, error) {
	der := []byte(s)
	if block, _ := pem.Decode([]byte(s)); block != nil {
		der = block.Bytes
	} else if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		der = raw
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	return ec, nil
}

func selfSignedCert(k *ecdsa.PrivateKey) ([][]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	return [][]byte{cert}, nil
}
