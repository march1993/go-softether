package adapter

// Packet an Ethernet packet
type Packet []byte

// PacketReadWriter packet reader & writer
type PacketReadWriter interface {
	Read() (p []Packet, err error)
	Write(p []Packet) (err error)
}

// Adapter network adapter
type Adapter interface {
	GetName() string // get network adapter name
	Destroy()
	PacketReadWriter
}

// CreateLocalMachineAdapter create an virtual network adapter on host machine
func CreateLocalMachineAdapter(name string, mac string) (Adapter, error) {
	return createLocalMachineAdapter(name, mac)
}

func InvokeDHCP(a Adapter) error {
	return invokeDHCP(a)
}
