package mayaqua

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
)

// Sock used by go-softether
type Sock struct {
	io.ReadWriteCloser
	reader   *bufio.Reader
	RemoteIP string
}

func (s *Sock) Read(p []byte) (n int, err error) {
	return s.reader.Read(p)
}

// Write hack
// func (s *Sock) Write(p []byte) (n int, err error) {
// 	fmt.Println("sending:", string(p))
// 	return s.ReadWriteCloser.Write(p)
// }

// NewSock new sock
func NewSock(s *tls.Conn) *Sock {
	return &Sock{
		ReadWriteCloser: s,
		reader:          bufio.NewReader(s),
		RemoteIP:        s.RemoteAddr().(*net.TCPAddr).IP.String(),
	}
}
