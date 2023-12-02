package benchmark

/*
 void uprobe_target() {}
*/
import "C"

func uprobeCgo() {
	C.uprobe_target()
}

func uprobeGo() {}
