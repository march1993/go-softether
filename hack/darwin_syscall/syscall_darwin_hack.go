package syscall

import (
	"unsafe"
)

const SizeofSockaddrNDRV = 18

type RawSockaddrNDRV struct {
	Len    uint8
	Family uint8
	Name   [16]uint8
}

type SockaddrNDRV struct {
	Name string
	raw  RawSockaddrNDRV
}

func (sa *SockaddrNDRV) sockaddr() (ptr unsafe.Pointer, _len _Socklen, err error) {
	sa.raw.Len = SizeofSockaddrNDRV
	sa.raw.Family = AF_NDRV
	for i := 0; i < len(sa.Name); i++ {
		sa.raw.Name[i] = sa.Name[i]
	}
	return unsafe.Pointer(&sa.raw), _Socklen(sa.raw.Len), nil
}
