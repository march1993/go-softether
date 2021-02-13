package cedar

import (
	"bytes"
	"crypto/tls"
	"errors"
	"go-softether/mayaqua"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

var sessionCache tls.ClientSessionCache

func init() {
	sessionCache = tls.NewLRUClientSessionCache(0)
}

// ClientConnectToServer Client connect to server
func (c *Connection) ClientConnectToServer() (*mayaqua.Sock, error) {
	tlsConf := tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
		ServerName:         c.Host,
		ClientSessionCache: sessionCache,
	}

	if r, err := net.Dial("tcp", c.Host+":"+strconv.Itoa(c.Port)); nil != err {
		return nil, err
	} else {
		s := tls.Client(r, &tlsConf)
		sock := mayaqua.NewSock(s, r)
		c.firstSock = sock
		return sock, nil
	}
}

// ClientUploadSignature Upload a signature
func (c *Connection) ClientUploadSignature(s *mayaqua.Sock) (*http.Request, error) {
	randSize := int(rand.Uint32() % (mayaqua.HTTP_PACK_RAND_SIZE_MAX * 2))
	waterSize := len(WaterMark) + randSize
	water := make([]uint8, waterSize)
	copy(water, WaterMark)
	rand.Read(water[len(WaterMark):])

	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path: mayaqua.HTTP_VPN_TARGET2,
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       s.RemoteIP,
		Body:       ioutil.NopCloser(bytes.NewReader(water)),
		Header: http.Header{
			"Content-Type": []string{mayaqua.HTTP_CONTENT_TYPE3},
		},
		ContentLength: int64(waterSize),
	}

	return req, req.Write(s)
}

// ClientDownloadHello Download the Hello packet
func (c *Connection) ClientDownloadHello(s *mayaqua.Sock, req *http.Request) (err error) {

	if pack, err := mayaqua.HttpClientRecv(s, req); nil != err {
		return err
	} else {
		if e := pack.GetError(); 0 != e {
			return errors.New("Error code: " + strconv.Itoa(int(e)))
		}
		if random, ver, build, serverStr, err := GetHello(pack); nil != err {
			return err
		} else {
			c.ServerVer = ver
			c.ServerBuild = build
			c.ServerStr = serverStr

			if c.firstSock == s {
				c.Random = random
			}
		}

		return nil
	}
}

// ErrInvalidHello invalid hello
var ErrInvalidHello = errors.New("Invalid hello")

// GetHello get hello from the pack
func GetHello(p *mayaqua.Pack) (random [mayaqua.SHA1_SIZE]byte, ver, build uint32, serverStr string, err error) {
	if serverStr = p.GetStr("hello"); "" == serverStr {
		err = ErrInvalidHello
		return
	}
	ver = p.GetInt("version")
	build = p.GetInt("build")
	if p.GetDataSize("random") != mayaqua.SHA1_SIZE {
		err = ErrInvalidHello
		return
	}

	copy(random[:], p.GetData("random"))
	return
}

// ClientUploadAuth client upload auth
func (c *Connection) ClientUploadAuth() (*http.Request, error) {
	a := &c.Session.ClientAuth
	o := &c.Session.ClientOption

	var p *mayaqua.Pack
	if !c.UseTicket {
		switch a.AuthType {
		case CLIENT_AUTHTYPE_ANONYMOUS:
			p = PackLoginWithAnonymous(o.HubName, a.Username)
		case CLIENT_AUTHTYPE_PASSWORD:
			securePassword := SecurePassword(a.HashedPassword, c.Random)
			p = PackLoginWithPassword(o.HubName, a.Username, securePassword)
		case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
			panic("unsafe!")
		case CLIENT_AUTHTYPE_CERT:
			panic("unimplemented")
		case CLIENT_AUTHTYPE_OPENSSLENGINE:
			panic("unimplemented")
		case CLIENT_AUTHTYPE_SECURE:
			panic("unimplemented")
		default:
			panic("invalid")
		}
	} else {
		p = &mayaqua.Pack{}
		p.AddStr("method", "login")
		p.AddStr("hubname", o.HubName)
		p.AddStr("username", a.Username)
		p.AddInt("authtype", uint32(AUTHTYPE_TICKET))
		p.AddData("ticket", c.Ticket[:])
	}

	if nil == p {
		return nil, ERR_PROTOCOL_ERROR
	}

	c.PackAddClientVersion(p)

	// Protocol
	p.AddInt("protocol", uint32(c.Protocol))

	// Version, etc.
	p.AddStr("hello", c.ClientStr)
	p.AddInt("version", c.ClientVer)
	p.AddInt("build", c.ClientBuild)
	p.AddInt("client_id", c.Cedar.ClientId)

	// The maximum number of connections
	p.AddInt("max_connection", o.MaxConnection)
	// Flag to use of cryptography
	p.AddBool("use_encrypt", o.UseEncrypt)
	// Data compression flag
	p.AddBool("use_compress", o.UseCompress)
	// Half connection flag
	p.AddBool("half_connection", o.HalfConnection)

	// Bridge / routing mode flag
	p.AddBool("require_bridge_routing_mode", o.RequireBridgeRoutingMode)

	// Monitor mode flag
	p.AddBool("require_monitor_mode", o.RequireMonitorMode)

	// VoIP / QoS flag
	p.AddBool("qos", !o.DisableQoS)

	// Bulk transfer support
	p.AddBool("support_bulk_on_rudp", true)
	p.AddBool("support_hmac_on_bulk_of_rudp", true)

	// UDP recovery support
	p.AddBool("support_udp_recovery", true)

	// Unique ID
	unique := GenerateMachineUniqueHash()
	p.AddData("unique_id", unique[:])

	// UDP acceleration function using flag
	if o.NoUdpAcceleration == false && nil != c.Session.UdpAccel {
		// TODO: UDP acceleration
	}

	p.AddInt("rudp_bulk_max_version", 2)

	// Brand string for the connection limit
	p.AddStr("branded_ctos", "Branded_VPN")

	// Node information
	info := c.CreateNodeInfo()
	OutRpcNodeInfo(p, info)

	// OS information
	v := GetWinVer()
	OutRpcWinVer(p, v)

	return mayaqua.HttpClientSend(c.firstSock, p)
}

// ClientUploadAuth2 client upload additional auth
func (c *Connection) ClientUploadAuth2() (*http.Request, error) {
	p := &mayaqua.Pack{}
	p.AddStr("method", "additional_connect")
	p.AddData("session_key", c.Session.SessionKey[:])
	c.PackAddClientVersion(p)
	return mayaqua.HttpClientSend(c.firstSock, p)
}

// PackLoginWithAnonymous pack login with anonymouse
func PackLoginWithAnonymous(hubname, username string) *mayaqua.Pack {
	// Validate arguments
	if hubname == "" || username == "" {
		return nil
	}

	p := &mayaqua.Pack{}
	p.AddStr("method", "login")
	p.AddStr("hubname", hubname)
	p.AddStr("username", username)
	p.AddInt("authtype", uint32(CLIENT_AUTHTYPE_ANONYMOUS))

	return p
}

// PackLoginWithPassword pack login with password
func PackLoginWithPassword(hubname, username string, securePassword mayaqua.Sha1Sum) *mayaqua.Pack {
	// Validate arguments
	if hubname == "" || username == "" {
		return nil
	}

	p := &mayaqua.Pack{}
	p.AddStr("method", "login")
	p.AddStr("hubname", hubname)
	p.AddStr("username", username)
	p.AddInt("authtype", uint32(CLIENT_AUTHTYPE_PASSWORD))
	p.AddData("secure_password", securePassword[:])

	return p
}

// PackAddClientVersion pack add client version
func (c *Connection) PackAddClientVersion(p *mayaqua.Pack) {
	p.AddStr("client_str", c.ClientStr)
	p.AddInt("client_ver", c.ClientVer)
	p.AddInt("client_build", c.ClientBuild)
}

// GenerateMachineUniqueHash generate machine unique hash
func GenerateMachineUniqueHash() mayaqua.Sha1Sum {
	// TODO: better one
	buf := make([]byte, 64)
	rand.Read(buf)
	return mayaqua.Sha0(buf)
}

// CreateNodeInfo create node info
func (c *Connection) CreateNodeInfo() NodeInfo {
	// TODO:
	return NodeInfo{
		ClientProductName:  "",
		ClientProductVer:   0,
		ClientProductBuild: 0,
		ServerProductName:  "",
		ServerProductVer:   0,
		ServerProductBuild: 0,
		ClientOsName:       "",
		ClientOsVer:        "",
		ClientOsProductId:  "",
		ClientHostname:     "",
		ClientIpAddress:    0,
		ClientPort:         0,
		ServerHostname:     "",
		ServerIpAddress:    0,
		ServerPort:         0,
		ProxyHostname:      "",
		ProxyIpAddress:     0,
		ProxyPort:          0,
		HubName:            c.Session.ClientOption.HubName,
		UniqueId:           [16]byte{},
		ClientIpAddress6:   [16]byte{},
		ServerIpAddress6:   [16]byte{},
		ProxyIpAddress6:    [16]byte{},
		Padding:            [256]byte{},
	}
}

// ParseWelcomeFromPack parse welcome from pack
func ParseWelcomeFromPack(p *mayaqua.Pack) (sessionName, connectionName string, policy Policy) {
	sessionName = p.GetStr("session_name")
	connectionName = p.GetStr("connection_name")
	policy = PackGetPolicy(p)

	return
}

// PackGetPolicy get policy from pack
func PackGetPolicy(p *mayaqua.Pack) Policy {
	po := Policy{}
	PackGetPolicyBool := func(k string) bool {
		return p.GetBool("policy:" + k)
	}

	po.Access = PackGetPolicyBool("Access")
	po.DHCPFilter = PackGetPolicyBool("DHCPFilter")
	po.DHCPNoServer = PackGetPolicyBool("DHCPNoServer")
	po.DHCPForce = PackGetPolicyBool("DHCPForce")
	po.NoBridge = PackGetPolicyBool("NoBridge")
	po.NoRouting = PackGetPolicyBool("NoRouting")
	po.PrivacyFilter = PackGetPolicyBool("PrivacyFilter")
	po.NoServer = PackGetPolicyBool("NoServer")
	po.CheckMac = PackGetPolicyBool("CheckMac")
	po.CheckIP = PackGetPolicyBool("CheckIP")
	po.ArpDhcpOnly = PackGetPolicyBool("ArpDhcpOnly")
	po.MonitorPort = PackGetPolicyBool("MonitorPort")
	po.NoBroadcastLimiter = PackGetPolicyBool("NoBroadcastLimiter")
	po.FixPassword = PackGetPolicyBool("FixPassword")
	po.NoQoS = PackGetPolicyBool("NoQoS")
	// Ver 3
	po.RSandRAFilter = PackGetPolicyBool("RSandRAFilter")
	po.RAFilter = PackGetPolicyBool("RAFilter")
	po.DHCPv6Filter = PackGetPolicyBool("DHCPv6Filter")
	po.DHCPv6NoServer = PackGetPolicyBool("DHCPv6NoServer")
	po.NoRoutingV6 = PackGetPolicyBool("NoRoutingV6")
	po.CheckIPv6 = PackGetPolicyBool("CheckIPv6")
	po.NoServerV6 = PackGetPolicyBool("NoServerV6")
	po.NoSavePassword = PackGetPolicyBool("NoSavePassword")
	po.FilterIPv4 = PackGetPolicyBool("FilterIPv4")
	po.FilterIPv6 = PackGetPolicyBool("FilterIPv6")
	po.FilterNonIP = PackGetPolicyBool("FilterNonIP")
	po.NoIPv6DefaultRouterInRA = PackGetPolicyBool("NoIPv6DefaultRouterInRA")
	po.NoIPv6DefaultRouterInRAWhenIPv6 = PackGetPolicyBool("NoIPv6DefaultRouterInRAWhenIPv6")

	PackGetPolicyUint := func(k string) uint32 {
		return p.GetInt("policy:" + k)
	}

	// UINT value
	// Ver 2
	po.MaxConnection = PackGetPolicyUint("MaxConnection")
	po.TimeOut = PackGetPolicyUint("TimeOut")
	po.MaxMac = PackGetPolicyUint("MaxMac")
	po.MaxIP = PackGetPolicyUint("MaxIP")
	po.MaxUpload = PackGetPolicyUint("MaxUpload")
	po.MaxDownload = PackGetPolicyUint("MaxDownload")
	po.MultiLogins = PackGetPolicyUint("MultiLogins")
	// Ver 3
	po.MaxIPv6 = PackGetPolicyUint("MaxIPv6")
	po.AutoDisconnect = PackGetPolicyUint("AutoDisconnect")
	po.VLanId = PackGetPolicyUint("VLanId")

	// Ver 3 flag
	po.Ver3 = PackGetPolicyBool("Ver3")

	return po

}

// ErrInvalidSessionKey invalid session key
var ErrInvalidSessionKey = errors.New("ErrInvalidSessionKey")

// GetSessionKeyFromPack get session key from pack
func GetSessionKeyFromPack(p *mayaqua.Pack) (sessionKey mayaqua.Sha1Sum, sessionKey32 uint32, err error) {
	if k := p.GetData("session_key"); int(mayaqua.SHA1_SIZE) != len(k) {
		err = ErrInvalidSessionKey
	} else {
		copy(sessionKey[:], k)
	}

	sessionKey32 = p.GetInt("session_key_32")
	return
}
