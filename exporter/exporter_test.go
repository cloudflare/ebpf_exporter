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
			value:  8,
		},
		{
			labels: []string{"bar"},
			value:  1,
		},
		{
			labels: []string{"foo"},
			value:  3,
		},
	}

	aggregated := aggregateMapValues(values)

	sort.Slice(aggregated, func(i, j int) bool {
		return aggregated[i].value > aggregated[j].value
	})

	expected := []aggregatedMetricValue{
		{
			labels: []string{"foo"},
			value:  11,
		},
		{
			labels: []string{"bar"},
			value:  1,
		},
	}

	if !reflect.DeepEqual(aggregated, expected) {
		t.Errorf("expected after aggregation: %#v, got: %#v", expected, aggregated)
	}
}

func TestAggregatedMetricValuesEmptyLabels(t *testing.T) {
	// labels can be empty if we skipped a label, for example with regexp
	values := []metricValue{
		{
			labels: []string{},
			value:  8,
		},
		{
			labels: []string{"foo"},
			value:  2,
		},
		{
			labels: []string{"foo"},
			value:  4,
		},
	}

	aggregated := aggregateMapValues(values)
	expected := []aggregatedMetricValue{
		{
			labels: []string{"foo"},
			value:  6,
		},
	}

	if !reflect.DeepEqual(aggregated, expected) {
		t.Errorf("expected after aggregation: %#v, got: %#v", expected, aggregated)
	}
}
