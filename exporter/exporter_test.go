package exporter

import (
	"reflect"
	"testing"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/decoder"
)

func TestDecodeLabel(t *testing.T) {
	for _, tc := range []struct {
		key      string
		labels   []config.Label
		expected []string
	}{
		{
			key: `0x2 "Handler-main"`,
			labels: []config.Label{
				{
					Name: "op",
					Decoders: []config.Decoder{
						{Name: "uint64"},
						{Name: "static_map", StaticMap: map[string]string{"1": "refs", "2": "slow", "3": "miss"}},
					},
				},
				{
					Name: "command",
					Decoders: []config.Decoder{
						{Name: "string"},
					},
				},
			},
			expected: []string{"slow", "Handler-main"},
		},
		{
			key: `0x2 "tmux: server"`,
			labels: []config.Label{
				{
					Name: "op",
					Decoders: []config.Decoder{
						{Name: "static_map", StaticMap: map[string]string{"0x1": "refs", "0x2": "slow", "0x3": "miss"}},
					},
				},
				{
					Name: "command",
					Decoders: []config.Decoder{
						{Name: "string"},
					},
				},
			},
			expected: []string{"slow", "tmux: server"},
		},
	} {
		t.Run(tc.key, func(t *testing.T) {
			e := &Exporter{decoders: decoder.NewSet()}
			decoded, _, err := e.extractLabels(tc.key, tc.labels)
			if !reflect.DeepEqual(decoded, tc.expected) {
				t.Errorf("failed to decode: expected(%v), got decoded=%v, err=%q", tc.expected, decoded, err)
			}
		})
	}
}
