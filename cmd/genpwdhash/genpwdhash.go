package main

import (
	"encoding/base64"
	"fmt"
	"go-softether/mayaqua"
	"os"
	"strings"
)

func main() {
	if 3 != len(os.Args) {
		fmt.Printf("Usage: %s <username> <password>\n", os.Args[0])
		return
	}

	username := strings.ToUpper(os.Args[1])
	password := os.Args[2]
	result := mayaqua.Sha0([]byte(password + username))
	str := base64.StdEncoding.EncodeToString(result[:])
	fmt.Println(str)
}
