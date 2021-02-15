package adapter

import (
	"fmt"
	"net"
)

func printPackets(name string, p []Packet) {
	fmt.Println(name, len(p), "packet(s)")
	for idx, p := range p {
		dst, src := net.HardwareAddr(p[:6]).String(), net.HardwareAddr(p[6:12]).String()
		if dst == "5e:d4:ed:6f:fb:0c" || src == "5e:d4:ed:6f:fb:0c" {
			fmt.Println("#", idx, "len:", len(p), src, "=>", dst)
		}

	}
}
