package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"go-softether/adapter"
	"go-softether/cedar"
	"go-softether/mayaqua"
	"os"
	"os/signal"
	"syscall"
)

var (
	// ErrBadHashedPassword bad hashed password
	ErrBadHashedPassword = errors.New("ErrBadHashedPassword")
)

func main() {
	if err := connectToServer(config.Host, config.Port, config.Username, config.HashedPassword, config.HubName, config.InsecureSkipVerify); nil != err {
		fmt.Println("error: " + err.Error())
	}
}

func connectToServer(host string, port int, username, hashedPassword, hubName string, insecureSkipVerify bool) error {
	session := cedar.Session{}
	session.ClientAuth.AuthType = cedar.CLIENT_AUTHTYPE_PASSWORD
	session.ClientAuth.Username = username

	conn := cedar.Connection{
		Cedar:              cedar.NewCedar(),
		Host:               host,
		Port:               port,
		ClientVer:          1000,
		ClientBuild:        1000,
		ClientStr:          "Go-SoftEther Client",
		Session:            &session,
		InsecureSkipVerify: insecureSkipVerify,
	}

	session.Connection = &conn

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
	conn.Session.ClientOption.UseEncrypt = true

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

		var welcome *mayaqua.Pack
		if req, err := conn.ClientUploadAuth(); nil != err {
			return err
		} else if p, err := mayaqua.HttpClientRecv(s, req); nil != err {
			return err
		} else if e := p.GetError(); 0 != e {
			return cedar.ErrorCode(e)
		} else if brandedCfroms := p.GetStr("branded_cfroms"); len(brandedCfroms) > 0 && "Branded_VPN" != brandedCfroms {
			return cedar.ERR_BRANDED_C_FROM_S
		} else {
			welcome = p
		}

		// TODO: client update notification

		if msg := string(welcome.GetData("Msg")); "" != msg {
			// TODO: msg from server
		}

		if welcome.GetInt("Redirect") != 0 {
			// TODO: redirect
		}

		// fmt.Println("use_fast_rc4:", welcome.GetInt("use_fast_rc4"))
		sessionName, connectionName, policy := cedar.ParseWelcomeFromPack(welcome)
		fmt.Println("SessionName:", sessionName, "ConnectionName:", connectionName)

		// fmt.Printf("state: %+v\n", c.Conn.ConnectionState())

		if sessionKey, sessionKey32, err := cedar.GetSessionKeyFromPack(welcome); nil != err {
			return err
		} else {
			conn.Session.SessionKey = sessionKey
			conn.Session.SessionKey32 = sessionKey32
		}

		if welcome.GetInt("use_encrypt") == 0 {
			return errors.New("use_encrypt is false")
		}
		conn.Session.Policy.MaxConnection = welcome.GetInt("max_connection")

		// TODO: Deploy and update connection parameters

		conn.Name = connectionName

		conn.Session.Name = sessionName
		conn.Session.Policy = policy

		conn.StartTunnelingMode()

		left, err := adapter.CreateLocalMachineAdapter("feth0", config.LocalAdapterMAC)
		if nil != err {
			return err
		}
		defer left.Destroy()

		right, err := conn.Session.Main()
		if nil != err {
			return err
		}
		defer right.Destroy()

		go func() {
			_ = adapter.InvokeDHCP(left)
		}()

		c := make(chan os.Signal)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			left.Destroy()
			right.Destroy()
			os.Exit(0)
		}()

		return pipe(left, right)
	}
}

func pipe(left, right adapter.Adapter) error {
	f := func(left, right adapter.Adapter) error {
		for {
			ps, err := left.Read()
			if nil != err {
				return err
			}
			err = right.Write(ps)
			if nil != err {
				return err
			}
		}
	}

	go f(left, right)
	return f(right, left)
}
