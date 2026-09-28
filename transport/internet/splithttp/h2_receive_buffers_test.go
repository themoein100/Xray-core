package splithttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
)

// Checks the windows the client puts on the wire: the stream window is the initial window size in
// its SETTINGS, and the connection cap is the increment of its first WINDOW_UPDATE on stream 0
// (both x/net and net/http grant the configured value on top of the 65535-byte default).
func TestNewLimitedH2TransportAdvertisesWindows(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	var streamWindow, connWindow uint32
	tr := newLimitedH2Transport(context.Background())
	tr.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		c, err := tls.Dial(network, srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
		if err != nil {
			return nil, err
		}
		return &frameSniffer{Conn: c, stream: &streamWindow, conn: &connWindow}, nil
	}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if streamWindow != h2MaxReceiveBufferPerStream {
		t.Errorf("stream window = %d, want %d", streamWindow, h2MaxReceiveBufferPerStream)
	}
	if connWindow != h2MaxReceiveBufferPerConnection {
		t.Errorf("connection window = %d, want %d", connWindow, h2MaxReceiveBufferPerConnection)
	}
}

// frameSniffer parses the frames the client writes after the connection preface.
type frameSniffer struct {
	net.Conn
	buf          []byte
	stream, conn *uint32
}

func (s *frameSniffer) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	b := s.buf
	if len(b) >= len(http2.ClientPreface) && string(b[:len(http2.ClientPreface)]) == http2.ClientPreface {
		b = b[len(http2.ClientPreface):]
	}
	for len(b) >= 9 {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 9+n {
			break
		}
		typ, streamID, payload := b[3], uint32(b[5]&0x7f)<<24|uint32(b[6])<<16|uint32(b[7])<<8|uint32(b[8]), b[9:9+n]
		switch {
		case typ == 0x4 && b[4]&0x1 == 0: // SETTINGS, not ACK
			for i := 0; i+6 <= len(payload); i += 6 {
				if id := uint16(payload[i])<<8 | uint16(payload[i+1]); id == 0x4 { // INITIAL_WINDOW_SIZE
					*s.stream = uint32(payload[i+2])<<24 | uint32(payload[i+3])<<16 | uint32(payload[i+4])<<8 | uint32(payload[i+5])
				}
			}
		case typ == 0x8 && streamID == 0 && *s.conn == 0: // first connection-level WINDOW_UPDATE
			*s.conn = uint32(payload[0]&0x7f)<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
		}
		b = b[9+n:]
	}
	return s.Conn.Write(p)
}
