package warpmasque

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/api"
	"golang.org/x/crypto/curve25519"
)

// TestDumpAccounts registers fresh WARP identities for manual chain tests.
func TestDumpAccounts(t *testing.T) {
	out := os.Getenv("MASQUE_DUMP")
	if out == "" {
		t.Skip("set MASQUE_DUMP=<file>")
	}
	res := map[string]any{}
	for _, name := range []string{"masque1", "masque2"} {
		acct, err := api.Register("PC", "en_US", "", true)
		if err != nil {
			t.Fatal(err)
		}
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(k)
		pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		a2, _, err := api.EnrollKey(acct, pub, "")
		if err != nil {
			t.Fatal(err)
		}
		res[name] = map[string]any{"privateKey": base64.StdEncoding.EncodeToString(der),
			"endpointPublicKey": a2.Config.Peers[0].PublicKey, "address": a2.Config.Interface.Addresses.V4}
	}
	for _, name := range []string{"wg1", "wg2"} {
		var priv [32]byte
		rand.Read(priv[:])
		pubKey, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
		body, _ := json.Marshal(map[string]any{"key": base64.StdEncoding.EncodeToString(pubKey), "install_id": "", "fcm_token": "",
			"type": "Android", "locale": "en_US", "tos": time.Now().UTC().Format(time.RFC3339)})
		req, _ := http.NewRequest("POST", "https://api.cloudflareclient.com/v0a1922/reg", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("CF-Client-Version", "a-6.3-1922")
		req.Header.Set("User-Agent", "okhttp/3.12.1")
		rsp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var r struct {
			Config struct {
				ClientID  string `json:"client_id"`
				Interface struct {
					Addresses struct{ V4, V6 string } `json:"addresses"`
				} `json:"interface"`
				Peers []struct {
					PublicKey string `json:"public_key"`
				} `json:"peers"`
			} `json:"config"`
		}
		json.NewDecoder(rsp.Body).Decode(&r)
		rsp.Body.Close()
		cid, _ := base64.StdEncoding.DecodeString(r.Config.ClientID)
		reserved := []int{0, 0, 0}
		if len(cid) >= 3 {
			reserved = []int{int(cid[0]), int(cid[1]), int(cid[2])}
		}
		res[name] = map[string]any{"secretKey": base64.StdEncoding.EncodeToString(priv[:]), "peerPublicKey": r.Config.Peers[0].PublicKey,
			"address": r.Config.Interface.Addresses.V4, "reserved": reserved}
	}
	b, _ := json.MarshalIndent(res, "", " ")
	os.WriteFile(out, b, 0600)
}
