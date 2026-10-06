package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/masque"
	"google.golang.org/protobuf/proto"
)

// MasqueConfig is the "masque" outbound: Cloudflare WARP over HTTP/3 CONNECT-IP.
type MasqueConfig struct {
	PrivateKey        string   `json:"privateKey"`
	EndpointPublicKey string   `json:"endpointPublicKey"`
	Endpoint          string   `json:"endpoint"`
	SNI               string   `json:"sni"`
	Address           []string `json:"address"`
	MTU               int32    `json:"mtu"`
	DNS               []string `json:"dns"`
}

func (c *MasqueConfig) Build() (proto.Message, error) {
	if c.PrivateKey == "" || c.EndpointPublicKey == "" || c.Endpoint == "" {
		return nil, errors.New("masque: privateKey, endpointPublicKey and endpoint are required")
	}
	if len(c.Address) == 0 {
		return nil, errors.New("masque: address is required")
	}
	return &masque.Config{
		PrivateKey:        c.PrivateKey,
		EndpointPublicKey: c.EndpointPublicKey,
		Endpoint:          c.Endpoint,
		Sni:               c.SNI,
		Addresses:         c.Address,
		Mtu:               c.MTU,
		Dns:               c.DNS,
	}, nil
}
