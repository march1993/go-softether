package cedar

import (
	"fmt"
	"go-softether/mayaqua"
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
func (se *Session) Main() error {
	s := se.Connection.tcp[0]

	// WTF: I don't know why the following line is needed, other wise, an OpenSSL protocol version unsupported error is returned
	s.WTFWriteRaw([]byte{0, 1, 2, 3, 4})

	go func() {
		if true {
			return
		}

		if s, err := se.Connection.ClientConnectToServer(); nil != err {
			panic(err)
		} else {
			if req, err := se.Connection.ClientUploadSignature(s); nil != err {
				panic(err)
			} else if err := se.Connection.ClientDownloadHello(s, req); nil != err {
				panic(err)
			}

			var welcome *mayaqua.Pack
			if req, err := se.Connection.ClientUploadAuth(); nil != err {
				panic(err)
			} else if p, err := mayaqua.HttpClientRecv(s, req); nil != err {
				panic(err)
			} else if e := p.GetError(); 0 != e {
				// fmt.Printf("%+v\n", p)
				// for _, e := range p.Elements {
				// 	fmt.Printf("%+v\n", e)
				// }
				panic(ErrorCode(e).Error())
			} else if brandedCfroms := p.GetStr("branded_cfroms"); len(brandedCfroms) > 0 && "Branded_VPN" != brandedCfroms {
				panic(ERR_BRANDED_C_FROM_S)
			} else {
				welcome = p
			}

			for _, e := range welcome.Elements {
				fmt.Printf("addele: %+v\n", e)
			}
			direction := welcome.GetInt("direction")
			fmt.Println("additional direction:", direction)

			go func() {
				for {
					alive := []byte{255, 255, 255, 255, 0, 0, 0, 37, 236, 183, 104, 30, 220, 134, 245, 10, 46, 10, 13, 48, 102, 152, 43, 158, 85, 142, 47, 5, 211, 48, 32, 23, 117, 161, 101, 242, 4, 73, 23, 241, 0, 127, 15, 221, 6}
					// alive = []byte{0, 0, 0, 1, 0, 0, 0, 0}
					if _, err := s.Write(alive); nil != err {
						panic(err)
					}
					fmt.Println("additional: sent zero num")
					// return
					time.Sleep(1 * time.Second)
				}
			}()
			for {
				buf := make([]byte, 1500)
				// s.Conn
				fmt.Println("additional begin:", time.Now().Local().String())
				if n, err := s.Read(buf); nil != err {
					fmt.Println("n:", n, "error:", time.Now().Local().String())
					fmt.Printf("error: %+v\n", err)
					panic(err)
				} else {
					fmt.Println("additional received: ", n)
					// fmt.Printf("%x\n", buf[:n])
					fmt.Println(buf[:n])
				}
				fmt.Println("additional end:", time.Now().Local().String())
			}
		}
	}()
	go func() {

		for {
			alive := []byte{255, 255, 255, 255, 0, 0, 0, 37, 236, 183, 104, 30, 220, 134, 245, 10, 46, 10, 13, 48, 102, 152, 43, 158, 85, 142, 47, 5, 211, 48, 32, 23, 117, 161, 101, 242, 4, 73, 23, 241, 0, 127, 15, 221, 6}

			if _, err := s.Write(alive); nil != err {
				panic(err)
			}

			fmt.Println("sent zero num")
			// return
			time.Sleep(1 * time.Second)
		}
	}()
	for {
		buf := make([]byte, 1500)
		// s.Conn
		fmt.Println("begin:", time.Now().Local().String())
		if n, err := s.Read(buf); nil != err {
			fmt.Println("n:", n, "error:", time.Now().Local().String())
			fmt.Printf("error: %+v\n", err)
			return err
		} else {
			fmt.Println("received[1]: ", n)
			// fmt.Printf("%x\n", buf[:n])
			fmt.Println(buf[:n])
		}
		fmt.Println("end:", time.Now().Local().String())
	}
}
