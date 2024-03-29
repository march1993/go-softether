package mayaqua

import (
	"bufio"
	"crypto/tls"
	"net"
)

// Sock used by go-softether
type Sock struct {
	conn     *tls.Conn
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

func (s *Sock) Write(p []byte) (n int, err error) {
	return s.conn.Write(p)
}

func (s *Sock) Close() error {
	return s.conn.Close()
}

// NewSock new sock
func NewSock(s *tls.Conn, r net.Conn) *Sock {
	return &Sock{
		conn:     s,
		raw:      r,
		reader:   bufio.NewReader(s),
		RemoteIP: s.RemoteAddr().(*net.TCPAddr).IP.String(),
	}
}
