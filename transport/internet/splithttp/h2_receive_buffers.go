package splithttp

import (
	"context"
	"net/http"
	"reflect"
	"unsafe"

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

// limitH2ReceiveBuffers applies the windows above to a standalone http2.Transport.
//
// The legacy http2.Transport exposes no field for them: it only reads them from the net/http
// Transport it is attached to (the unexported t1, via its HTTP2 config). A standalone transport
// has none, so this attaches an otherwise-empty one carrying just those two values. An empty t1
// changes nothing else — every other t1 setting it consults is zero, which is the same as having
// no t1. If a future x/net drops the field, the transport keeps its defaults and this logs it.
func limitH2ReceiveBuffers(ctx context.Context, transport *http2.Transport) {
	field := reflect.ValueOf(transport).Elem().FieldByName("t1")
	if !field.IsValid() || field.Type() != reflect.TypeOf((*http.Transport)(nil)) || !field.CanAddr() {
		errors.LogWarning(ctx, "XHTTP: http2 receive buffers left at x/net defaults (transport layout changed)")
		return
	}
	t1 := &http.Transport{
		HTTP2: &http.HTTP2Config{
			MaxReceiveBufferPerStream:     h2MaxReceiveBufferPerStream,
			MaxReceiveBufferPerConnection: h2MaxReceiveBufferPerConnection,
		},
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(t1))
}
