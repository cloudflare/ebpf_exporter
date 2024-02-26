package main

/*
void
#if defined(__clang__)
__attribute__ ((optnone))
#endif
enable_kernel_tracing() { }
*/
import "C"

func enableKernelTracing() {
	C.enable_kernel_tracing()
}
