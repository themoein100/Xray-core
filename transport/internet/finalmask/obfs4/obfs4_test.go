package obfs4_test

import (
	"io"
	"net"
	"testing"

	o4 "gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"

	"github.com/xtls/xray-core/transport/internet/finalmask/obfs4"
)

// A stock obfs4 server (what lyrebird/obfs4proxy runs) must accept the mask's client and echo data both ways.
func TestClientAgainstStockServer(t *testing.T) {
	sf, err := (&o4.Transport{}).ServerFactory(t.TempDir(), &pt.Args{})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := sf.Args().Get("cert")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		conn, err := sf.WrapConn(raw)
		if err != nil {
			raw.Close()
			return
		}
		io.Copy(conn, conn)
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := (&obfs4.Config{Cert: cert, IatMode: 0}).WrapConnClient(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("hello through obfs4")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q err=%v", got, err)
	}
}

func TestBadCert(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := (&obfs4.Config{Cert: "nope", IatMode: 0}).WrapConnClient(a); err == nil {
		t.Fatal("expected error for bad cert")
	}
}
