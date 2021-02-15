package adapter

import (
	"fmt"
	"net"
)

const debug = false

func printPackets(name string, p []Packet) {
	if debug {
		fmt.Println(name, len(p), "packet(s)")
		for idx, p := range p {
			dst, src := net.HardwareAddr(p[:6]).String(), net.HardwareAddr(p[6:12]).String()
			fmt.Println("#", idx, "len:", len(p), src, "=>", dst)
		}
	}
}
