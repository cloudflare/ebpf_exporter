package util

import (
	"encoding/binary"
	"unsafe"
)

var byteOrder binary.ByteOrder

func init() {
	byteOrder = initHostByteOrder()
}

func initHostByteOrder() binary.ByteOrder {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xAABB)

	if buf[0] == 0xBB {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

// GetHostByteOrder returns the current byte-order.
func GetHostByteOrder() binary.ByteOrder {
	return byteOrder
}
