package exporter

/*
void post_attach_mark() {}
*/
import "C"

func postAttachMark() {
	// This function is called when all programs are loaded and attached,
	// allowing ebpf code to run an initialization step by attaching a uprobe.
	C.post_attach_mark()
}
