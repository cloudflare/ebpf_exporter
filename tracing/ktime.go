package tracing

/*
#include <time.h>
static unsigned long long get_nsecs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"
import "time"

func ktime() uint64 {
	return uint64(C.get_nsecs())
}

func ktimeToTime(ts uint64) time.Time {
	return time.Now().Add(time.Duration(ts - ktime()))
}
