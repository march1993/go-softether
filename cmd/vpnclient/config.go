package main

import (
	"encoding/json"
	"os"
)

var config struct {
	Username       string
	HashedPassword string
	Host           string
	Port           int
	HubName        string
}

func init() {
	if file, openErr := os.Open("config.json"); nil != openErr {
		panic("Error: No config.json")
	} else {
		defer file.Close()

		decoder := json.NewDecoder(file)
		if decodeErr := decoder.Decode(&config); nil != decodeErr {
			panic(decodeErr.Error())
		}

	}
}
