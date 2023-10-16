package tracing

import (
	"testing"
	"time"
)

func TestKernelTime(t *testing.T) {
	before := time.Now()
	now := ktimeToTime(ktime())
	after := time.Now()

	beforeToNow := now.Sub(before)
	nowToAfter := after.Sub(now)

	if beforeToNow < 0 {
		t.Errorf("ktime is older than regular time taken before it: %v", beforeToNow)
	}

	if beforeToNow.Milliseconds() > 1 {
		t.Errorf("regular time to ktime drifted too much: %v", beforeToNow)
	}

	if nowToAfter < 0 {
		t.Errorf("ktime is newer than regular time taken after it: %v", nowToAfter)
	}

	if nowToAfter.Milliseconds() > 1 {
		t.Errorf("ktime to regular time drifted too much: %v", nowToAfter)
	}

	t.Logf("ktime drift: %v .. ktime .. %v", beforeToNow, nowToAfter)
}
