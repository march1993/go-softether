package cedar

import (
	"go-softether/mayaqua"
)

// SecurePassword calculate hash of password+random
func SecurePassword(password, random mayaqua.Sha1Sum) mayaqua.Sha1Sum {
	buf := append(password[:], random[:]...)
	return mayaqua.Sha0(buf)
}
