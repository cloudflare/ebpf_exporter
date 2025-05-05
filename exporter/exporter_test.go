package exporter

import (
	"reflect"
	"sort"
	"testing"
)

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
