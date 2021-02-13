package cedar

// PolicyItem structure
type PolicyItem struct {
	Index        uint32
	TypeInt      bool
	AllowZero    bool
	MinValue     uint32
	MaxValue     uint32
	DefaultValue uint32
	FormatStr    string
}

// Policy structure
type Policy struct {
	// For Ver 2.0
	Access             bool   // Grant access
	DHCPFilter         bool   // Filter DHCP packets (IPv4)
	DHCPNoServer       bool   // Prohibit the behavior of the DHCP server (IPv4)
	DHCPForce          bool   // Force DHCP-assigned IP address (IPv4)
	NoBridge           bool   // Prohibit the bridge behavior
	NoRouting          bool   // Prohibit the router behavior (IPv4)
	CheckMac           bool   // Prohibit the duplicate MAC address
	CheckIP            bool   // Prohibit a duplicate IP address (IPv4)
	ArpDhcpOnly        bool   // Prohibit the broadcast other than ARP, DHCP, ICMPv6
	PrivacyFilter      bool   // Privacy filter mode
	NoServer           bool   // Prohibit to operate as a TCP/IP server (IPv4)
	NoBroadcastLimiter bool   // Not to limit the number of broadcast
	MonitorPort        bool   // Allow monitoring mode
	MaxConnection      uint32 // Maximum number of TCP connections
	TimeOut            uint32 // Communication time-out period
	MaxMac             uint32 // Maximum number of MAC address
	MaxIP              uint32 // Maximum number of IP address (IPv4)
	MaxUpload          uint32 // Upload bandwidth
	MaxDownload        uint32 // Download bandwidth
	FixPassword        bool   // User can not change password
	MultiLogins        uint32 // Multiple logins limit
	NoQoS              bool   // Prohibit the use of VoIP / QoS features

	// For Ver 3.0
	RSandRAFilter                   bool   // Filter the Router Solicitation / Advertising packet (IPv6)
	RAFilter                        bool   // Filter the router advertisement packet (IPv6)
	DHCPv6Filter                    bool   // Filter DHCP packets (IPv6)
	DHCPv6NoServer                  bool   // Prohibit the behavior of the DHCP server (IPv6)
	NoRoutingV6                     bool   // Prohibit the router behavior (IPv6)
	CheckIPv6                       bool   // Prohibit the duplicate IP address (IPv6)
	NoServerV6                      bool   // Prohibit to operate as a TCP/IP server (IPv6)
	MaxIPv6                         uint32 // Maximum number of IP address (IPv6)
	NoSavePassword                  bool   // Prohibit to save the password in the VPN Client
	AutoDisconnect                  uint32 // Disconnect the VPN Client automatically at a certain period of time
	FilterIPv4                      bool   // Filter all IPv4 packets
	FilterIPv6                      bool   // Filter all IPv6 packets
	FilterNonIP                     bool   // Filter all non-IP packets
	NoIPv6DefaultRouterInRA         bool   // Delete the default router specification from the IPv6 router advertisement
	NoIPv6DefaultRouterInRAWhenIPv6 bool   // Delete the default router specification from the IPv6 router advertisement (Enable IPv6 connection)
	VLanId                          uint32 // Specify the VLAN ID

	Ver3 bool // Whether version 3.0
}
