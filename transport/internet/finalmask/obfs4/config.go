package obfs4

import (
	"net"
	"strconv"

	o4 "gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"

	"github.com/xtls/xray-core/common/errors"
)

// Obfs4 in finalmask mode is the stock obfs4 (Lyrebird) client handshake and framing run over the raw TCP
// connection, so a plain obfs4proxy/lyrebird server in front of the real inbound can terminate it.
// Only the client side exists: the server must be a regular obfs4 bridge.
func (c *Config) WrapConnClient(raw net.Conn) (net.Conn, error) {
	factory, err := (&o4.Transport{}).ClientFactory("")
	if err != nil {
		return nil, err
	}
	args, err := factory.ParseArgs(&pt.Args{
		"cert":     {c.Cert},
		"iat-mode": {strconv.Itoa(int(c.IatMode))},
	})
	if err != nil {
		return nil, errors.New("invalid obfs4 settings").Base(err)
	}
	conn, err := factory.Dial("tcp", "", func(string, string) (net.Conn, error) { return raw, nil }, args)
	if err != nil {
		return nil, errors.New("obfs4 handshake failed").Base(err)
	}
	return conn, nil
}

func (c *Config) WrapConnServer(net.Conn) (net.Conn, error) {
	return nil, errors.New("obfs4 mask is client only; run an obfs4 bridge (lyrebird/obfs4proxy) on the server")
}
