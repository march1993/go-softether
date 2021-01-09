package cedar

import (
	"bytes"
	"crypto/tls"
	"errors"
	"go-softether/mayaqua"
	"io/ioutil"
	"math/rand"
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
		// CipherSuites:       []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
		ServerName:         c.Host,
		ClientSessionCache: sessionCache,
	}

	s, err := tls.Dial("tcp", c.Host+":"+strconv.Itoa(c.Port), &tlsConf)
	sock := mayaqua.NewSock(s)
	if nil == err {
		c.firstSock = sock
	}
	return sock, err
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
