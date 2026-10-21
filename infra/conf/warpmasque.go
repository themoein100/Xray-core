package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/warpmasque"
	"google.golang.org/protobuf/proto"
)

// WarpMasqueConfig is the "warp-masque" outbound: Cloudflare WARP over HTTP/3 CONNECT-IP.
type WarpMasqueConfig struct {
	PrivateKey        string   `json:"privateKey"`
	EndpointPublicKey string   `json:"endpointPublicKey"`
	Endpoint          string   `json:"endpoint"`
	SNI               string   `json:"sni"`
	Address           []string `json:"address"`
	MTU               int32    `json:"mtu"`
	DNS               []string `json:"dns"`
	Transport         string   `json:"transport"`
	Fragment          bool     `json:"fragment"`
	FragmentSize      string   `json:"fragmentSize"`
	FragmentDelay     string   `json:"fragmentDelay"`
	TLSGroups         string   `json:"tlsGroups"`
	Chain             bool     `json:"chain"`
}

func (c *WarpMasqueConfig) Build() (proto.Message, error) {
	if c.PrivateKey == "" || c.EndpointPublicKey == "" || c.Endpoint == "" {
		return nil, errors.New("masque: privateKey, endpointPublicKey and endpoint are required")
	}
	switch c.Transport {
	case "", "h3", "h2":
	default:
		return nil, errors.New("masque: transport must be h3 or h2")
	}
	if len(c.Address) == 0 {
		return nil, errors.New("masque: address is required")
	}
	return &warpmasque.Config{
		PrivateKey:        c.PrivateKey,
		EndpointPublicKey: c.EndpointPublicKey,
		Endpoint:          c.Endpoint,
		Sni:               c.SNI,
		Addresses:         c.Address,
		Mtu:               c.MTU,
		Dns:               c.DNS,
		Transport:         c.Transport,
		Fragment:          c.Fragment,
		FragmentSize:      c.FragmentSize,
		FragmentDelay:     c.FragmentDelay,
		TlsGroups:         c.TLSGroups,
		Chain:             c.Chain,
	}, nil
}
