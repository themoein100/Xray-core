package warpmasque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/api"
)

func TestH2Live(t *testing.T) {
	if os.Getenv("MASQUE_LIVE") == "" {
		t.Skip("set MASQUE_LIVE=1")
	}
	acct, err := api.Register("PC", "en_US", "", true)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	acct2, _, err := api.EnrollKey(acct, pub, "")
	if err != nil {
		t.Fatal(err)
	}
	ep := os.Getenv("MASQUE_EP")
	tun := &tunnel{conf: &Config{
		PrivateKey: base64.StdEncoding.EncodeToString(der), EndpointPublicKey: acct2.Config.Peers[0].PublicKey,
		Endpoint: ep, Sni: os.Getenv("MASQUE_SNI"), Addresses: []string{acct2.Config.Interface.Addresses.V4},
		Transport: os.Getenv("MASQUE_TR"), Fragment: os.Getenv("MASQUE_FRAG") != "",
		TlsGroups: os.Getenv("MASQUE_GROUPS"),
	}, ready: make(chan struct{})}
	if err := tun.launch(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := tun.wait(ctx); err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Transport: &http.Transport{DialContext: tun.tnet.DialContext}, Timeout: 15 * time.Second}
	rsp, err := c.Get("https://1.1.1.1/cdn-cgi/trace")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rsp.Body)
	t.Logf("%s", b)
}
