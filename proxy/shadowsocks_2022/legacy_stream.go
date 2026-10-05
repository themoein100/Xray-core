package shadowsocks_2022

import (
	"context"

	shadowsocks "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowstream"
	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

// Client-only support for the legacy stream ciphers (aes-*-cfb, aes-*-ctr, rc4-md5, chacha20-ietf,
// xchacha20). Many public servers still use them. They ride on this outbound so the config layer
// can route them the same way as 2022 methods; Key carries the password.

// IsLegacyStreamMethod reports whether method is one of the legacy stream ciphers.
func IsLegacyStreamMethod(method string) bool {
	for _, m := range shadowstream.List {
		if m == method {
			return true
		}
	}
	return false
}

func newLegacyStreamClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config.Key == "" {
		return nil, errors.New("missing password")
	}
	method, err := shadowstream.New(config.Method, nil, config.Key)
	if err != nil {
		return nil, errors.New("create method").Base(err)
	}
	v := core.MustFromContext(ctx)
	return &Outbound{
		server: net.Destination{
			Address: config.Address.AsAddress(),
			Port:    net.Port(config.Port),
			Network: net.Network_TCP,
		},
		legacy:        method,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func toSocksaddr(dest net.Destination) M.Socksaddr {
	return M.ParseSocksaddrHostPort(dest.Address.String(), uint16(dest.Port))
}

func (o *Outbound) processLegacyStream(ctx context.Context, link *transport.Link, conn net.Conn, destination net.Destination, timer *signal.ActivityTimer, sessionPolicy policy.Session) error {
	var requestDone, responseDone func() error

	if destination.Network == net.Network_TCP {
		serverConn := o.legacy.DialEarlyConn(conn, toSocksaddr(destination))
		requestDone = func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			// The request header goes out with the first write. Send it right away even when the
			// client has nothing yet, so server-first protocols are not left waiting.
			if timeoutReader, ok := link.Reader.(buf.TimeoutReader); ok {
				if mb, err := timeoutReader.ReadMultiBufferTimeout(0); err == nil && !mb.IsEmpty() {
					if err := buf.NewWriter(serverConn).WriteMultiBuffer(mb); err != nil {
						return errors.New("write payload").Base(err)
					}
					return buf.Copy(link.Reader, buf.NewWriter(serverConn), buf.UpdateActivity(timer))
				}
			}
			if _, err := serverConn.Write(nil); err != nil {
				return errors.New("client handshake").Base(err)
			}
			return buf.Copy(link.Reader, buf.NewWriter(serverConn), buf.UpdateActivity(timer))
		}
		responseDone = func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(serverConn), link.Writer, buf.UpdateActivity(timer))
		}
	} else {
		packetConn := o.legacy.DialPacketConn(conn)
		requestDone = func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, &legacyPacketWriter{conn: packetConn, dest: destination}, buf.UpdateActivity(timer))
		}
		responseDone = func() error {
			defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
			return buf.Copy(&legacyPacketReader{conn: packetConn}, link.Writer, buf.UpdateActivity(timer))
		}
	}

	responseDonePost := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDonePost); err != nil {
		return errors.New("connection ends").Base(err)
	}
	return nil
}

// legacyPacketHeadroom fits the salt (at most 32 bytes) and the longest SOCKS address in front of a packet.
const legacyPacketHeadroom = 512

type legacyPacketWriter struct {
	conn N.NetPacketConn
	dest net.Destination
}

func (w *legacyPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		dest := w.dest
		if b.UDP != nil {
			dest = *b.UDP
		}
		packet := B.NewSize(legacyPacketHeadroom + int(b.Len()))
		packet.Resize(legacyPacketHeadroom, 0)
		_, _ = packet.Write(b.Bytes())
		// WritePacket releases packet
		if err := w.conn.WritePacket(packet, toSocksaddr(dest)); err != nil {
			return err
		}
	}
	return nil
}

type legacyPacketReader struct {
	conn N.NetPacketConn
}

func (r *legacyPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	packet := B.NewPacket()
	defer packet.Release()
	from, err := r.conn.ReadPacket(packet)
	if err != nil {
		return nil, err
	}
	b := buf.New()
	if _, err := b.Write(packet.Bytes()); err != nil {
		b.Release()
		return nil, err
	}
	var src net.Destination
	if from.IsFqdn() {
		src = net.UDPDestination(net.DomainAddress(from.Fqdn), net.Port(from.Port))
	} else {
		src = net.UDPDestination(net.IPAddress(from.Addr.AsSlice()), net.Port(from.Port))
	}
	b.UDP = &src
	return buf.MultiBuffer{b}, nil
}

var _ shadowsocks.Method = (*shadowstream.Method)(nil)
