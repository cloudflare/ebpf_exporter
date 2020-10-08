package exporter

import (
	"fmt"
	"math"

	"github.com/cloudflare/ebpf_exporter/config"
)

type histogramWithLabels struct {
	labels  []string
	buckets map[float64]uint64
}

type histogramKeyer func(bucket float64) float64

func histogramKeyerMaker(histogram config.Histogram) (histogramKeyer, error) {
	multiplier := histogram.BucketMultiplier
	if multiplier == 0 {
		multiplier = 1
	}

	switch histogram.BucketType {
	case config.HistogramBucketExp2:
		return func(bucket float64) float64 {
			return math.Exp2(bucket) * multiplier
		}, nil
	case config.HistogramBucketLinear:
		return func(bucket float64) float64 {
			return bucket * multiplier
		}, nil
	case config.HistogramBucketFixed:
		return func(bucket float64) float64 {
			return bucket * multiplier
		}, nil
	default:
		return nil, fmt.Errorf("unknown histogram type: %q", histogram.BucketType)
	}
}

func transformHistogram(buckets map[float64]uint64, histogram config.Histogram) (transformed map[float64]uint64, count uint64, sum float64, err error) {
	if histogram.BucketType == config.HistogramBucketFixed {
		return transformHistogramFixed(buckets, histogram)
	}
	return transformHistogramDynamic(buckets, histogram)
}

func transformHistogramDynamic(buckets map[float64]uint64, histogram config.Histogram) (transformed map[float64]uint64, count uint64, sum float64, err error) {
	keyer, err := histogramKeyerMaker(histogram)
	if err != nil {
		return nil, 0, 0, err
	}

	size := histogram.BucketMax - histogram.BucketMin
	if size == 0 {
		return nil, 0, 0, fmt.Errorf("histogram buckets have zero size: [bucket_min .. bucket_max] = [%d .. %d]", histogram.BucketMin, histogram.BucketMax)
	}

	transformed = make(map[float64]uint64, size)

	// Histograms coming from kernels may have missing entries,
	// but we must provide consistent view for prometheus.
	// This is why we build the list of possible buickets from
	// configuration and backfill missing ones.
	for i := float64(histogram.BucketMin); i <= float64(histogram.BucketMax); i++ {
		// Prometheus expects cumulative buckets with bucket being
		// the upper limit of all values in the bucket.
		count += buckets[i]

		transformed[keyer(i)] = count
	}

	multiplier := histogram.BucketMultiplier
	if multiplier == 0 {
		multiplier = 1
	}

	// Optional sum key
	sum = float64(buckets[float64(histogram.BucketMax+1)]) * multiplier

	return
}

func transformHistogramFixed(buckets map[float64]uint64, histogram config.Histogram) (transformed map[float64]uint64, count uint64, sum float64, err error) {
	keyer, err := histogramKeyerMaker(histogram)
	if err != nil {
		return nil, 0, 0, err
	}

	size := len(histogram.BucketKeys)
	if size == 0 {
		return nil, 0, 0, fmt.Errorf("histogram buckets have zero size: len(bucket_keys) = %d", len(histogram.BucketKeys))
	}

	transformed = make(map[float64]uint64, size)

	for i := 0; i < len(histogram.BucketKeys); i++ {
		key := histogram.BucketKeys[i]

		// Prometheus expects cumulative buckets with bucket being
		// the upper limit of all values in the bucket.
		count += buckets[key]

		transformed[keyer(key)] = count
	}

	multiplier := histogram.BucketMultiplier
	if multiplier == 0 {
		multiplier = 1
	}

	// Optional sum key
	sum = float64(buckets[histogram.BucketKeys[len(histogram.BucketKeys)-1]+1]) * multiplier

	return
}
