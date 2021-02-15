package cedar

import (
	"encoding/binary"
	"go-softether/adapter"
	"go-softether/mayaqua"
	"io"
	"io/ioutil"
	"math/rand"
	"time"
)

// Session structure
type Session struct {
	Connection   *Connection
	ClientAuth   ClientAuth
	ClientOption ClientOption

	UdpAccel *UdpAccel

	Name         string // session name
	Policy       Policy
	SessionKey   mayaqua.Sha1Sum
	SessionKey32 uint32
}

// NodeInfo node information
type NodeInfo struct {
	ClientProductName  string // Client product name
	ClientProductVer   uint32 // Client version
	ClientProductBuild uint32 // Client build number
	ServerProductName  string // Server product name
	ServerProductVer   uint32 // Server version
	ServerProductBuild uint32 // Server build number
	ClientOsName       string // Client OS name
	ClientOsVer        string // Client OS version
	ClientOsProductId  string // Client OS Product ID
	ClientHostname     string // Client host name
	ClientIpAddress    uint32 // Client IP address
	ClientPort         uint32 // Client port number
	ServerHostname     string // Server host name
	ServerIpAddress    uint32 // Server IP address
	ServerPort         uint32 // Server port number
	ProxyHostname      string // Proxy host name
	ProxyIpAddress     uint32 // Proxy Server IP Address
	ProxyPort          uint32 // Proxy port number
	HubName            string // HUB name

	UniqueId [16]byte // Unique ID
	// The following is for IPv6 support
	ClientIpAddress6 [16]byte             // Client IPv6 address
	ServerIpAddress6 [16]byte             // Server IP address
	ProxyIpAddress6  [16]byte             // Proxy Server IP Address
	Padding          [304 - (16 * 3)]byte // Padding
}

// Main main
func (se *Session) Main() (adapter.Adapter, error) {
	s := se.Connection.tcp[0]

	// WTF: I don't know why the following line is needed, other wise, an OpenSSL protocol version unsupported error is returned
	s.WTFWriteRaw([]byte{0, 1, 2, 3, 4})

	sessionAdapter := &sessionAdapter{
		Session: se,
		l2r:     make(chan []adapter.Packet, 16),
		r2l:     make(chan []adapter.Packet, 16),
	}

	go func() {
		// local to remote
		for {
			sz := uint32(0)
			if err := binary.Read(s, binary.BigEndian, &sz); nil != err {
				// TODO: reconnect
				return
			}

			if sz == KEEP_ALIVE_MAGIC {
				binary.Read(s, binary.BigEndian, &sz)
				io.CopyN(ioutil.Discard, s, int64(sz))
			} else {
				ps := make([]adapter.Packet, 0, sz)
				for idx := int64(sz); idx > 0; idx-- {
					binary.Read(s, binary.BigEndian, &sz)
					buf := make([]uint8, sz)
					io.ReadFull(s, buf)
					ps = append(ps, buf)
				}
				sessionAdapter.l2r <- ps
			}
		}

	}()
	go func() {
		// remote to local
		timer := time.NewTicker(time.Second * 3)
		rand := rand.New(rand.NewSource(time.Now().Unix()))
		for {
			select {
			case ps := <-sessionAdapter.r2l:
				sz := uint32(len(ps))
				binary.Write(s, binary.BigEndian, sz)
				for _, p := range ps {
					sz = uint32(len(p))
					binary.Write(s, binary.BigEndian, sz)
					s.Write(p)
				}

			case <-timer.C:
				sz := KEEP_ALIVE_MAGIC
				if err := binary.Write(s, binary.BigEndian, sz); nil != err {
					// TODO: reconnect
					return
				}
				sz = uint32(rand.Intn(int(MAX_KEEPALIVE_SIZE)))
				if sz == 0 {
					sz = 1
				}
				binary.Write(s, binary.BigEndian, sz)
				io.CopyN(s, rand, int64(sz))
			}
		}
	}()

	return sessionAdapter, nil
}
