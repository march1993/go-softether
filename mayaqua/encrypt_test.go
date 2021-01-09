package mayaqua

import (
	"encoding/base64"
	"testing"
)

func TestSha0(t *testing.T) {
	result := Sha0([]byte("password1" + "USERNAME1"))
	str := base64.StdEncoding.EncodeToString(result[:])
	expected := "yQutDhGqXao5a5j3FHs3jI7qazw="
	if expected != str {
		t.Error("sha0 failed")
	}
}
