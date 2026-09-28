package splithttp

import (
	"context"
	"net/http"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/http2"
)

// HTTP/2 receive windows for the XHTTP client.
//
// x/net's http2.Transport advertises a 4 MiB window per stream and 1 GiB per connection, and it
// buffers up to that much per stream whenever the reader falls behind. In stream-one mode every
// proxied TCP connection is one stream, so an image-heavy feed whose app-side consumer is slower
// than the server can hold tens of MiB of live Go heap — inside an iOS Network Extension that is
// killed outright at ~50 MB. The connection cap bounds the total no matter how many streams open.
//
// 512 KiB per stream still carries ~20 Mbit/s per stream at a 200 ms round trip, and 4 MiB per
// connection ~160 Mbit/s across all of them.
const (
	h2MaxReceiveBufferPerStream     = 512 << 10
	h2MaxReceiveBufferPerConnection = 4 << 20
)

// newLimitedH2Transport returns an http2.Transport whose receive windows are the ones above.
//
// http2.Transport has no field for them; both of its implementations read them from the net/http
// Transport it is bound to. With Go 1.27 x/net wraps net/http's built-in HTTP/2, which merges that
// Transport's HTTP2 config first; the legacy x/net client reads the same config through its t1.
// ConfigureTransports binds a fresh one carrying only these two values, so every other setting
// keeps its default, and it does so through public API on both paths.
//
// ConfigureTransports is meant for a Transport that net/http owns, so it gives the legacy client a
// pool that never dials. Clearing it restores the default pool, which dials via DialTLSContext.
func newLimitedH2Transport(ctx context.Context) *http2.Transport {
	t1 := &http.Transport{
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     h2MaxReceiveBufferPerStream,
			MaxReceiveBufferPerConnection: h2MaxReceiveBufferPerConnection,
		},
	}
	t2, err := http2.ConfigureTransports(t1)
	if err != nil {
		errors.LogWarningInner(ctx, err, "XHTTP: http2 receive buffers left at x/net defaults")
		return &http2.Transport{}
	}
	t2.ConnPool = nil
	return t2
}
