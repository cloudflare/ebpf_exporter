package exporter

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPopulateKaddrsFrom(t *testing.T) {
	e := &Exporter{kaddrs: map[string]uint64{}}
	kallsyms := strings.NewReader("ffffffff81000000 T builtin_symbol\n" +
		"ffffffffc0001000 t module_symbol\t[example]\n" +
		"ffffffffc0002000 t builtin_symbol\t[example]\n")

	if err := e.populateKaddrsFrom(kallsyms); err != nil {
		t.Fatal(err)
	}

	expected := map[string]uint64{
		"builtin_symbol": 0xffffffff81000000,
		"module_symbol":  0xffffffffc0001000,
	}
	if !reflect.DeepEqual(e.kaddrs, expected) {
		t.Errorf("expected kaddrs %#v, got %#v", expected, e.kaddrs)
	}
}

func TestAggregatedMetricValues(t *testing.T) {
	values := []metricValue{
		{
			labels: []string{"foo"},
			value:  []float64{8},
		},
		{
			labels: []string{"bar"},
			value:  []float64{1},
		},
		{
			labels: []string{"foo"},
			value:  []float64{3},
		},
	}

	aggregated := aggregateMapValues(values)

	sort.Slice(aggregated, func(i, j int) bool {
		return aggregated[i].value[0] > aggregated[j].value[0]
	})

	expected := []aggregatedMetricValue{
		{
			labels: []string{"foo"},
			value:  []float64{11},
		},
		{
			labels: []string{"bar"},
			value:  []float64{1},
		},
	}

	if !reflect.DeepEqual(aggregated, expected) {
		t.Errorf("expected after aggregation: %#v, got: %#v", expected, aggregated)
	}
}
