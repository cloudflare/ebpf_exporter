package tracing

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"
)

type traceContextKeyType int

const currentSpanIDKey traceContextKeyType = iota

// predeterminedIDGenerator is the same as randomIDGenerator from upstream,
// but it also tries to get a predetermined span id from the context if present.
type predeterminedIDGenerator struct {
	sync.Mutex
	randSource *rand.Rand
}

func newPredeterminedIDGenerator() *predeterminedIDGenerator {
	gen := &predeterminedIDGenerator{}
	gen.randSource = rand.New(rand.NewSource(time.Now().UnixNano()))
	return gen
}

// We try to get the predetermined spanID from the context first, falling back to generation if it's missing.
// See: https://github.com/open-telemetry/opentelemetry-go/blob/v1.19.0/sdk/trace/id_generator.go#L51
func (gen *predeterminedIDGenerator) NewSpanID(ctx context.Context, _ trace.TraceID) trace.SpanID {
	if id, ok := ctx.Value(currentSpanIDKey).(trace.SpanID); ok {
		return id
	}

	gen.Lock()
	defer gen.Unlock()
	sid := trace.SpanID{}
	_, _ = gen.randSource.Read(sid[:])
	return sid
}

// See: https://github.com/open-telemetry/opentelemetry-go/blob/v1.19.0/sdk/trace/id_generator.go#L61
func (gen *predeterminedIDGenerator) NewIDs(_ context.Context) (trace.TraceID, trace.SpanID) {
	gen.Lock()
	defer gen.Unlock()
	tid := trace.TraceID{}
	_, _ = gen.randSource.Read(tid[:])
	sid := trace.SpanID{}
	_, _ = gen.randSource.Read(sid[:])
	return tid, sid
}
