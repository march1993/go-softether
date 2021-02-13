package mayaqua

import (
	"bufio"
	"crypto/tls"
	"net"
)

// Sock used by go-softether
type Sock struct {
	*tls.Conn
	raw      net.Conn
	reader   *bufio.Reader
	RemoteIP string
}

// WTFWriteRaw WTF? see session.go
func (s *Sock) WTFWriteRaw(p []byte) (n int, err error) {
	return s.raw.Write(p)
}

func (s *Sock) Read(p []byte) (n int, err error) {
	return s.reader.Read(p)
}

// NewSock new sock
func NewSock(s *tls.Conn, r net.Conn) *Sock {
	return &Sock{
		Conn:     s,
		raw:      r,
		reader:   bufio.NewReaderSize(s, 32*1024),
		RemoteIP: s.RemoteAddr().(*net.TCPAddr).IP.String(),
	}
}
