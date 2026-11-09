package warpmasque

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	xerrors "github.com/xtls/xray-core/common/errors"
)

// Handshake diagnostics. Every line starts with "masque[diag]" so the app log can
// be filtered for it. The hooks record how far each attempt got — server
// certificate seen, client certificate requested — which is what separates a
// rejected device key from a TLS parameter mismatch when the endpoint only
// answers "handshake failure".

// diagDetailedAttempts attempts are logged in full; after that every
// diagEveryNth, so a dead endpoint does not flood the log once a second.
const (
	diagDetailedAttempts = 3
	diagEveryNth         = 10
)

type attemptTrace struct {
	serverCertSeen  atomic.Bool
	serverKeyMatch  atomic.Bool
	clientCertAsked atomic.Bool
	handshakeDone   atomic.Bool
	serverKeyFP     atomic.Value // string
	negotiated      atomic.Value // string
}

func (a *attemptTrace) reset() {
	a.serverCertSeen.Store(false)
	a.serverKeyMatch.Store(false)
	a.clientCertAsked.Store(false)
	a.handshakeDone.Store(false)
	a.serverKeyFP.Store("")
	a.negotiated.Store("")
}

func keyFingerprint(pub *ecdsa.PublicKey) string {
	if pub == nil {
		return "nil"
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "err:" + err.Error()
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

func curveNames(ids []tls.CurveID) string {
	if len(ids) == 0 {
		return "go-default"
	}
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = id.String()
	}
	return strings.Join(names, ",")
}

// instrumentTLS wraps the hooks PrepareTlsConfig installed without changing
// what they decide.
func instrumentTLS(cfg *tls.Config, tr *attemptTrace, peerKey *ecdsa.PublicKey) {
	verify := cfg.VerifyPeerCertificate
	cfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		tr.serverCertSeen.Store(true)
		if len(raw) > 0 {
			if c, err := x509.ParseCertificate(raw[0]); err == nil {
				if k, ok := c.PublicKey.(*ecdsa.PublicKey); ok {
					tr.serverKeyFP.Store(keyFingerprint(k))
					tr.serverKeyMatch.Store(k.Equal(peerKey))
				} else {
					tr.serverKeyFP.Store(fmt.Sprintf("non-ecdsa(%T)", c.PublicKey))
				}
			}
		}
		if verify != nil {
			return verify(raw, chains)
		}
		return nil
	}
	certs := cfg.Certificates
	cfg.GetClientCertificate = func(req *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		tr.clientCertAsked.Store(true)
		if len(certs) == 0 {
			return &tls.Certificate{}, nil
		}
		return &certs[0], nil
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		tr.handshakeDone.Store(true)
		tr.negotiated.Store(fmt.Sprintf("tls=%s cipher=%s alpn=%q curve=%s resumed=%v",
			tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite), cs.NegotiatedProtocol, cs.CurveID, cs.DidResume))
		return nil
	}
}

func (t *tunnel) logConfigSummary(ctx context.Context, privKey *ecdsa.PrivateKey, peerKey *ecdsa.PublicKey, sni string, cfg *tls.Config, mtu int) {
	transport := t.conf.Transport
	if transport == "" {
		transport = "h3"
	}
	xerrors.LogWarning(ctx, fmt.Sprintf(
		"masque[diag] config endpoint=%s transport=%s chain=%v sni=%s alpn=%v groups=%s(raw=%q) mtu=%d addrs=%v dns=%v fragment=%v clientKey=%s(%s) endpointKey=%s",
		t.conf.Endpoint, transport, t.conf.Chain, sni, cfg.NextProtos, curveNames(cfg.CurvePreferences), t.conf.TlsGroups,
		mtu, t.conf.Addresses, t.conf.Dns, t.conf.Fragment,
		keyFingerprint(&privKey.PublicKey), privKey.Curve.Params().Name, keyFingerprint(peerKey)))
}

// shouldLog decides whether attempt n gets a full diagnosis line.
func shouldLog(n int) bool {
	return n <= diagDetailedAttempts || n%diagEveryNth == 0
}

var tlsAlerts = map[uint8]string{
	10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate",
	43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
	46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
	50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
	80: "internal_error", 86: "inappropriate_fallback", 109: "missing_extension",
	110: "unsupported_extension", 112: "unrecognized_name", 116: "certificate_required",
	120: "no_application_protocol",
}

// diagnose turns a failed attempt into a stage, the raw error class, and a hint.
func diagnose(err error, tr *attemptTrace, sni string) string {
	stage := "before-server-hello"
	switch {
	case tr.handshakeDone.Load():
		stage = "after-tls(connect-ip)"
	case tr.clientCertAsked.Load():
		stage = "client-cert-sent"
	case tr.serverCertSeen.Load():
		stage = "server-cert-received"
	}
	parts := []string{"stage=" + stage}
	if fp, _ := tr.serverKeyFP.Load().(string); fp != "" {
		parts = append(parts, fmt.Sprintf("serverKey=%s match=%v", fp, tr.serverKeyMatch.Load()))
	}
	if n, _ := tr.negotiated.Load().(string); n != "" {
		parts = append(parts, n)
	}

	hint := ""
	var te *quic.TransportError
	var ie *quic.IdleTimeoutError
	var he *quic.HandshakeTimeoutError
	var ae *quic.ApplicationError
	switch {
	case errors.As(err, &te):
		code := uint64(te.ErrorCode)
		parts = append(parts, fmt.Sprintf("quicErr=0x%x remote=%v msg=%q", code, te.Remote, te.ErrorMessage))
		if code >= 0x100 && code <= 0x1ff {
			alert := uint8(code - 0x100)
			name := tlsAlerts[alert]
			if name == "" {
				name = "unknown"
			}
			parts = append(parts, fmt.Sprintf("tlsAlert=%d(%s)", alert, name))
			switch {
			case !te.Remote:
				hint = "local TLS rejected the server; check endpointPublicKey (serverKey match=false means wrong pinned key)"
			case stage == "client-cert-sent" || stage == "server-cert-received":
				hint = "server rejected the client certificate: privateKey is not an enrolled/active MASQUE device key (re-register with key_type=secp256r1 tunnel_type=masque)"
			case alert == 40 || alert == 47 || alert == 71:
				hint = "server rejected the ClientHello: check sni (" + sni + "), tlsGroups (try P-256 or X25519), endpoint IP/port"
			case alert == 112:
				hint = "SNI not accepted by this endpoint"
			case alert == 120:
				hint = "ALPN h3 not accepted; endpoint may not be a MASQUE endpoint"
			}
		}
	case errors.As(err, &he):
		hint = "no QUIC answer: UDP to endpoint blocked/filtered or wrong port; try transport=h2"
	case errors.As(err, &ie) && stage == "before-server-hello":
		hint = "no QUIC answer from endpoint: UDP to this address is blocked or dropped on this network; try another endpoint or transport=h2"
	case errors.As(err, &ie):
		hint = "QUIC went idle: UDP path lossy or blocked after handshake"
	case errors.As(err, &ae):
		parts = append(parts, fmt.Sprintf("appErr=0x%x remote=%v msg=%q", uint64(ae.ErrorCode), ae.Remote, ae.ErrorMessage))
	}
	if hint != "" {
		parts = append(parts, "hint="+hint)
	}
	return strings.Join(parts, " ")
}

func (t *tunnel) logAttempt(ctx context.Context, n int, started time.Time, err error, sni string) {
	if !shouldLog(n) {
		return
	}
	xerrors.LogWarning(ctx, fmt.Sprintf("masque[diag] attempt=%d elapsed=%s err=%v %s",
		n, time.Since(started).Round(time.Millisecond), err, diagnose(err, &t.trace, sni)))
}

// defaultGroups is the key-share preference when the config names none: P-256
// first, as the official WARP client offers, instead of Go's post-quantum
// default.
var defaultGroups = []tls.CurveID{tls.CurveP256, tls.X25519}

// attemptTLS returns the TLS config for one attempt. An explicit tlsGroups
// setting is honoured as is.
func (t *tunnel) attemptTLS(base *tls.Config, _ int) *tls.Config {
	if t.conf.TlsGroups != "" {
		return base
	}
	cfg := base.Clone()
	cfg.CurvePreferences = defaultGroups
	return cfg
}

// endpointUnusable reports whether this address is no use from here: it refused
// the ClientHello itself, or never answered at all (UDP to it is dropped, which
// mobile carriers do per address).
func endpointUnusable(err error, tr *attemptTrace) bool {
	if tr.serverCertSeen.Load() {
		return false
	}
	var te *quic.TransportError
	if errors.As(err, &te) {
		return te.Remote && te.ErrorCode == 0x128
	}
	var ie *quic.IdleTimeoutError
	var he *quic.HandshakeTimeoutError
	return errors.As(err, &ie) || errors.As(err, &he)
}

// tcpCandidates is the h2 dial order: first (when set), then the configured
// endpoint, then the gateways on TCP 443.
func tcpCandidates(configured, first string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	add(first)
	add(configured)
	for _, a := range h2Candidates(configured) {
		add(a)
	}
	return out
}
