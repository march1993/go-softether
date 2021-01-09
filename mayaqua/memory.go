package mayaqua

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	INVALID_STRING = errors.New("Invalid string")
)

// ReadBufStr read string from buffer
func ReadBufStr(r io.Reader) (string, error) {
	num := uint32(0)
	if err := binary.Read(r, binary.BigEndian, &num); nil != err {
		return "", err
	}
	if num == 0 {
		return "", INVALID_STRING
	}
	num--
	buf := make([]byte, num)
	if _, err := io.ReadFull(r, buf); nil != err {
		return "", err
	}

	return string(buf), nil
}

// WriteBufStr write string to buffer
func WriteBufStr(w io.Writer, s string) error {
	b := []byte(s)
	num := uint32(len(b)) + 1
	if err := binary.Write(w, binary.BigEndian, &num); nil != err {
		return err
	}
	_, err := w.Write(b)
	return err
}
