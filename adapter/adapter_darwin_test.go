package adapter

import (
	"fmt"
	"testing"
)

func TestAdapter(t *testing.T) {
	a, err := CreateLocalMachineAdapter("feth0", "11:22:33:44:55:66")
	fmt.Println("create error:", err)
	packets, err := a.Read()
	fmt.Println("err:", err)
	fmt.Println("#packets:", len(packets))
	for i, p := range packets {
		fmt.Println("#", i, " len:", len(p))
		fmt.Println(p)
	}
}
