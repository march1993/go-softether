package cedar

import (
	"go-softether/mayaqua"
)

// Connection structure
type Connection struct {
	Cedar              *Cedar
	Host               string
	Port               int
	InsecureSkipVerify bool // skip certificate and other checks

	UseTicket bool // Ticket using flag
	Ticket    [mayaqua.SHA1_SIZE]byte
	Name      string // Connection Name
	// CipherName string
	Session *Session

	ServerVer   uint32
	ServerBuild uint32
	ServerStr   string

	ClientVer   uint32
	ClientBuild uint32
	ClientStr   string

	Protocol ConnectionProtocol

	// ssl
	firstSock *mayaqua.Sock

	// tcp
	tubeSock *mayaqua.Sock
	tcp      []*mayaqua.Sock

	// encrypt
	Random [mayaqua.SHA1_SIZE]byte

	// TODO
	IsInProc bool
}

// ClientAuth client authorization
type ClientAuth struct {
	AuthType       ClientAuthType
	Username       string
	HashedPassword [mayaqua.SHA1_SIZE]byte
	PlainPassword  string
}

// ClientOption client options
type ClientOption struct {
	HubName string

	MaxConnection  uint32
	UseEncrypt     bool
	UseCompress    bool
	HalfConnection bool

	RequireBridgeRoutingMode bool
	RequireMonitorMode       bool
	DisableQoS               bool
	NoUdpAcceleration        bool
}

// StartTunnelingMode start tunneling mode
func (c *Connection) StartTunnelingMode() {
	if c.Protocol == CONNECTION_TCP {
		if c.IsInProc {
			c.tubeSock = c.firstSock
		}

		c.tcp = append(c.tcp, c.firstSock)
		c.firstSock = nil
	} else {
		// TODO: UDP

	}
}
