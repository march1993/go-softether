package adapter

import "io"

// Adapter network adapter
type Adapter io.ReadWriter

// CreateLocalMachineAdapter create an virtual network adapter on host machine
func CreateLocalMachineAdapter(name string) (Adapter, error)
