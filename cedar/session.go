package cedar

// Session structure
type Session struct {
	ClientAuth   ClientAuth
	ClientOption ClientOption

	UdpAccel *UdpAccel
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
