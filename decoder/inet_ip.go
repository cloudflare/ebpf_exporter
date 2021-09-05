package decoder

import (
	"net"

	"github.com/cloudflare/ebpf_exporter/config"
)

// InetIP is a decoder that transforms an ip byte representation into a string
type InetIP struct{}

// Decode transforms an ip byte representation into a string
func (i *InetIP) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	ip := net.IP(in)
	return []byte(ip.String()), nil
}
