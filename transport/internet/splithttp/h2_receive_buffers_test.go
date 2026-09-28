package splithttp

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"golang.org/x/net/http2"
)

func TestLimitH2ReceiveBuffersAttachesConfig(t *testing.T) {
	tr := &http2.Transport{}
	limitH2ReceiveBuffers(context.Background(), tr)
	f := reflect.ValueOf(tr).Elem().FieldByName("t1")
	if !f.IsValid() || f.IsNil() {
		t.Fatal("t1 not set")
	}
	t1 := (*http.Transport)(f.UnsafePointer())
	if t1.HTTP2 == nil || t1.HTTP2.MaxReceiveBufferPerStream != h2MaxReceiveBufferPerStream ||
		t1.HTTP2.MaxReceiveBufferPerConnection != h2MaxReceiveBufferPerConnection {
		t.Fatalf("unexpected config: %+v", t1.HTTP2)
	}
}
