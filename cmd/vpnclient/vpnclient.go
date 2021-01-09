package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"go-softether/cedar"
	"go-softether/mayaqua"
)

var (
	// ErrBadHashedPassword bad hashed password
	ErrBadHashedPassword = errors.New("ErrBadHashedPassword")
)

func main() {
	if err := connectToServer(config.Host, config.Port, config.Username, config.HashedPassword, config.HubName); nil != err {
		fmt.Println("error: " + err.Error())
	}
}

func connectToServer(host string, port int, username, hashedPassword, hubName string) error {
	conn := cedar.Connection{
		Cedar:       cedar.NewCedar(),
		Host:        host,
		Port:        port,
		ClientVer:   1000,
		ClientBuild: 1000,
		ClientStr:   "Go-SoftEther Client",
	}
	conn.Session.ClientAuth.AuthType = cedar.CLIENT_AUTHTYPE_PASSWORD
	conn.Session.ClientAuth.Username = username

	// conn.Session.ClientAuth.HashedPassword = mayaqua.Sha0([]byte(password + strings.ToUpper(username)))
	if pwd, err := base64.StdEncoding.DecodeString(hashedPassword); nil != err {
		return err
	} else if int(mayaqua.SHA1_SIZE) != len(pwd) {
		return ErrBadHashedPassword
	} else {
		copy(conn.Session.ClientAuth.HashedPassword[:], pwd)
	}
	conn.Session.ClientOption.HubName = hubName
	conn.Session.ClientOption.MaxConnection = 1

	if s, err := conn.ClientConnectToServer(); nil != err {
		return err
	} else {

		// TODO: NewUdpAccel

		if req, err := conn.ClientUploadSignature(s); nil != err {
			return err
		} else if err := conn.ClientDownloadHello(s, req); nil != err {
			return err
		}

		// TODO: IsAdminPackSupportedServerProduct

		// ClientCheckServerCert unnecessary?

		if req, err := conn.ClientUploadAuth(); nil != err {
			return err
		} else if p, err := mayaqua.HttpClientRecv(s, req); nil != err {
			return err
		} else if e := p.GetError(); 0 != e {
			// fmt.Printf("%+v\n", p)
			// for _, e := range p.Elements {
			// 	fmt.Printf("%+v\n", e)
			// }
			return cedar.ErrorCode(e)
		} else if brandedCfroms := p.GetStr("branded_cfroms"); len(brandedCfroms) > 0 && "Branded_VPN" != brandedCfroms {
			return cedar.ERR_BRANDED_C_FROM_S
		} else {
			fmt.Printf("p: %+v\n", p)
		}

		// TODO: client update notification

		return nil
	}
}
