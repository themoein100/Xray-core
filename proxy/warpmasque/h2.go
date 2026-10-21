package warpmasque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	gonet "net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP/2 transport: the same CONNECT-IP session as over HTTP/3, carried on one
// extended CONNECT stream over TLS/TCP. Without QUIC there are no datagrams, so
// every IP packet travels as an HTTP Datagram capsule (RFC 9297) in DATA frames.
// It exists for networks that drop QUIC. The framing is done by hand so the
// session is one stream on one connection with drop-on-full writes, rather than
// an http.Client request body pipe.

const (
	h2StreamID         = 1
	h2WindowSize       = 4 << 20
	h2DialTimeout      = 10 * time.Second
	capsuleDatagram    = 0x00
	h2RequestProtocol  = "cf-connect-ip"
	h2DefaultSendLimit = 65535
)

type h2Session struct {
	conn   gonet.Conn
	framer *http2.Framer
	wmu    sync.Mutex // guards framer writes

	// Peer flow-control windows for what we send.
	fmu        sync.Mutex
	connWindow int64
	strWindow  int64
	initWindow int64

	packets chan []byte
	done    chan struct{}
	once    sync.Once
	err     error
}

func dialH2(ctx context.Context, tlsConfig *tls.Config, dial func(context.Context) (gonet.Conn, error), authority string, wrap func(gonet.Conn) gonet.Conn) (*h2Session, error) {
	cfg := tlsConfig.Clone()
	cfg.NextProtos = []string{http2.NextProtoTLS}

	dialCtx, cancel := context.WithTimeout(ctx, h2DialTimeout)
	defer cancel()
	raw, err := dial(dialCtx)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(wrap(raw), cfg)
	if err := conn.HandshakeContext(dialCtx); err != nil {
		raw.Close()
		return nil, err
	}
	// WARP's TCP endpoint completes TLS without selecting a protocol and then
	// speaks HTTP/2 regardless, so an empty ALPN result is prior knowledge.
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" && p != http2.NextProtoTLS {
		conn.Close()
		return nil, errors.New("endpoint did not negotiate h2 (got " + strconv.Quote(p) + ")")
	}

	s := &h2Session{
		conn:       conn,
		framer:     http2.NewFramer(conn, bufio.NewReader(conn)),
		connWindow: h2DefaultSendLimit,
		strWindow:  h2DefaultSendLimit,
		initWindow: h2DefaultSendLimit,
		packets:    make(chan []byte, 256),
		done:       make(chan struct{}),
	}
	s.framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	s.framer.MaxHeaderListSize = 64 << 10

	if err := s.handshake(dialCtx, authority); err != nil {
		conn.Close()
		return nil, err
	}
	go s.readLoop()
	return s, nil
}

func (s *h2Session) handshake(ctx context.Context, authority string) error {
	if dl, ok := ctx.Deadline(); ok {
		s.conn.SetDeadline(dl)
		defer s.conn.SetDeadline(time.Time{})
	}
	if _, err := io.WriteString(s.conn, http2.ClientPreface); err != nil {
		return err
	}
	if err := s.framer.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: h2WindowSize},
	); err != nil {
		return err
	}
	if err := s.framer.WriteWindowUpdate(0, h2WindowSize-65535); err != nil {
		return err
	}

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	// WARP does not take RFC 8441 extended CONNECT over HTTP/2 (no
	// SETTINGS_ENABLE_CONNECT_PROTOCOL; a :protocol pseudo-header is a stream
	// PROTOCOL_ERROR). It takes a classic CONNECT and names the protocol in a header,
	// as the official client does.
	for _, f := range [][2]string{
		{":method", "CONNECT"},
		{":authority", authority + ":443"},
		{"cf-connect-proto", h2RequestProtocol},
		{"pq-enabled", "false"},
		{"user-agent", ""},
	} {
		enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	if err := s.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: h2StreamID, BlockFragment: hbuf.Bytes(), EndHeaders: true,
	}); err != nil {
		return err
	}

	// Wait for the response headers, answering SETTINGS and PING on the way.
	for {
		f, err := s.framer.ReadFrame()
		if err != nil {
			return err
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if err := s.onSettings(f); err != nil {
				return err
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				s.framer.WritePing(true, f.Data)
			}
		case *http2.WindowUpdateFrame:
			s.onWindowUpdate(f)
		case *http2.MetaHeadersFrame:
			if f.StreamID != h2StreamID {
				continue
			}
			status := f.PseudoValue("status")
			if status != "200" {
				return errors.New("endpoint answered " + status)
			}
			return nil
		case *http2.RSTStreamFrame:
			return errors.New("endpoint reset the stream: " + f.ErrCode.String())
		case *http2.GoAwayFrame:
			return errors.New("endpoint sent GOAWAY: " + f.ErrCode.String())
		}
	}
}

func (s *h2Session) onSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	f.ForeachSetting(func(st http2.Setting) error {
		if st.ID == http2.SettingInitialWindowSize {
			s.fmu.Lock()
			s.strWindow += int64(st.Val) - s.initWindow
			s.initWindow = int64(st.Val)
			s.fmu.Unlock()
		}
		return nil
	})
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.framer.WriteSettingsAck()
}

func (s *h2Session) onWindowUpdate(f *http2.WindowUpdateFrame) {
	s.fmu.Lock()
	if f.StreamID == 0 {
		s.connWindow += int64(f.Increment)
	} else if f.StreamID == h2StreamID {
		s.strWindow += int64(f.Increment)
	}
	s.fmu.Unlock()
}

func (s *h2Session) readLoop() {
	var pending []byte
	for {
		f, err := s.framer.ReadFrame()
		if err != nil {
			s.fail(err)
			return
		}
		switch f := f.(type) {
		case *http2.DataFrame:
			if f.StreamID != h2StreamID {
				continue
			}
			data := f.Data()
			if n := uint32(len(data)); n > 0 {
				s.wmu.Lock()
				s.framer.WriteWindowUpdate(0, n)
				s.framer.WriteWindowUpdate(h2StreamID, n)
				s.wmu.Unlock()
			}
			pending = append(pending, data...)
			pending, err = s.parseCapsules(pending)
			if err != nil {
				s.fail(err)
				return
			}
			if f.StreamEnded() {
				s.fail(errors.New("endpoint closed the stream"))
				return
			}
		case *http2.SettingsFrame:
			if err := s.onSettings(f); err != nil {
				s.fail(err)
				return
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				s.wmu.Lock()
				s.framer.WritePing(true, f.Data)
				s.wmu.Unlock()
			}
		case *http2.WindowUpdateFrame:
			s.onWindowUpdate(f)
		case *http2.RSTStreamFrame:
			if f.StreamID == h2StreamID {
				s.fail(errors.New("endpoint reset the stream: " + f.ErrCode.String()))
				return
			}
		case *http2.GoAwayFrame:
			s.fail(errors.New("endpoint sent GOAWAY: " + f.ErrCode.String()))
			return
		}
	}
}

// parseCapsules consumes every complete capsule in b and returns the remainder.
func (s *h2Session) parseCapsules(b []byte) ([]byte, error) {
	for len(b) > 0 {
		typ, n1, err := quicvarint.Parse(b)
		if err != nil {
			return b, nil // incomplete header
		}
		length, n2, err := quicvarint.Parse(b[n1:])
		if err != nil {
			return b, nil
		}
		end := n1 + n2 + int(length)
		if length > 1<<16 {
			return nil, errors.New("capsule too large")
		}
		if len(b) < end {
			return b, nil
		}
		payload := b[n1+n2 : end]
		if typ == capsuleDatagram && len(payload) > 0 {
			// Unlike RFC 9297 over HTTP/3, WARP's HTTP/2 DATAGRAM capsule holds the IP
			// packet itself, with no context ID in front.
			pkt := append([]byte(nil), payload...)
			select {
			case s.packets <- pkt:
			default: // reader is behind; drop like a congested link would
			}
		}
		b = b[end:]
	}
	return b[:0], nil
}

func (s *h2Session) ReadPacket(b []byte) (int, error) {
	select {
	case pkt := <-s.packets:
		return copy(b, pkt), nil
	case <-s.done:
		return 0, s.err
	}
}

// WritePacket sends one IP packet. When the peer's flow-control window is
// exhausted the packet is dropped instead of blocking; the inner TCP retransmits.
func (s *h2Session) WritePacket(pkt []byte) error {
	select {
	case <-s.done:
		return s.err
	default:
	}
	body := make([]byte, 0, len(pkt)+12)
	body = quicvarint.Append(body, capsuleDatagram)
	body = quicvarint.Append(body, uint64(len(pkt)))
	body = append(body, pkt...)

	need := int64(len(body))
	s.fmu.Lock()
	if s.connWindow < need || s.strWindow < need {
		s.fmu.Unlock()
		return nil
	}
	s.connWindow -= need
	s.strWindow -= need
	s.fmu.Unlock()

	s.wmu.Lock()
	err := s.framer.WriteData(h2StreamID, false, body)
	s.wmu.Unlock()
	if err != nil {
		s.fail(err)
	}
	return err
}

func (s *h2Session) fail(err error) {
	s.once.Do(func() {
		s.err = err
		close(s.done)
		s.conn.Close()
	})
}

func (s *h2Session) Close() error {
	s.fail(errors.New("closed"))
	return nil
}
