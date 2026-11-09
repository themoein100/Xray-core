package warpmasque

import (
	"strings"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestDiagnoseRemoteHandshakeFailure(t *testing.T) {
	var tr attemptTrace
	tr.reset()
	err := &quic.TransportError{Remote: true, ErrorCode: 0x128}
	got := diagnose(err, &tr, defaultSNI)
	for _, want := range []string{"stage=before-server-hello", "tlsAlert=40(handshake_failure)", "rejected the ClientHello"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
	tr.serverCertSeen.Store(true)
	tr.clientCertAsked.Store(true)
	if got := diagnose(err, &tr, defaultSNI); !strings.Contains(got, "client certificate") {
		t.Fatalf("got %q", got)
	}
}
