package cedar

import (
	"runtime"
	"strconv"
)

//////////////////////////////////////////////////////////////////////
//
// Connection-related constant
//
//////////////////////////////////////////////////////////////////////

// ConnectionProtocol connection protocol
type ConnectionProtocol uint32

const (
	CONNECTION_TCP             ConnectionProtocol = 0 // TCP protocol
	CONNECTION_UDP             ConnectionProtocol = 1 // UDP protocol
	CONNECTION_HUB_LAYER3      ConnectionProtocol = 6 // Layer-3 switch session
	CONNECTION_HUB_BRIDGE      ConnectionProtocol = 7 // Bridge session
	CONNECTION_HUB_SECURE_NAT  ConnectionProtocol = 8 // Secure NAT session
	CONNECTION_HUB_LINK_SERVER ConnectionProtocol = 9 // HUB link session
)
const (
	KEEP_ALIVE_MAGIC   uint32 = 0xffffffff
	MAX_KEEPALIVE_SIZE uint32 = 512
)

//////////////////////////////////////////////////////////////////////
//
// Type of user authentication
//
//////////////////////////////////////////////////////////////////////

// AuthType Constant in the server-side
type AuthType uint32

// ClientAuthType Constant of the client side
type ClientAuthType uint32

const (
	AUTHTYPE_ANONYMOUS    AuthType = 0  // Anonymous authentication
	AUTHTYPE_PASSWORD     AuthType = 1  // Password authentication
	AUTHTYPE_USERCERT     AuthType = 2  // User certificate authentication
	AUTHTYPE_ROOTCERT     AuthType = 3  // Root certificate which is issued by trusted Certificate Authority
	AUTHTYPE_RADIUS       AuthType = 4  // Radius authentication
	AUTHTYPE_NT           AuthType = 5  // Windows NT authentication
	AUTHTYPE_OPENVPN_CERT AuthType = 98 // TLS client certificate authentication
	AUTHTYPE_TICKET       AuthType = 99 // Ticket authentication

)

const (
	CLIENT_AUTHTYPE_ANONYMOUS      ClientAuthType = 0 // Anonymous authentication
	CLIENT_AUTHTYPE_PASSWORD       ClientAuthType = 1 // Password authentication
	CLIENT_AUTHTYPE_PLAIN_PASSWORD ClientAuthType = 2 // Plain password authentication
	CLIENT_AUTHTYPE_CERT           ClientAuthType = 3 // Certificate authentication
	CLIENT_AUTHTYPE_SECURE         ClientAuthType = 4 // Secure device authentication
	CLIENT_AUTHTYPE_OPENSSLENGINE  ClientAuthType = 5 // Openssl engine authentication
)

//////////////////////////////////////////////////////////////////////
//
// Error code
//
//////////////////////////////////////////////////////////////////////
type ErrorCode uint32

func (e ErrorCode) Error() string {
	return "Error Code: " + strconv.Itoa(int(e))
}

const (
	ERR_NO_ERROR                             ErrorCode = 0   // No error
	ERR_CONNECT_FAILED                       ErrorCode = 1   // Connection to the server has failed
	ERR_SERVER_IS_NOT_VPN                    ErrorCode = 2   // The destination server is not a VPN server
	ERR_DISCONNECTED                         ErrorCode = 3   // The connection has been interrupted
	ERR_PROTOCOL_ERROR                       ErrorCode = 4   // Protocol error
	ERR_CLIENT_IS_NOT_VPN                    ErrorCode = 5   // Connecting client is not a VPN client
	ERR_USER_CANCEL                          ErrorCode = 6   // User cancel
	ERR_AUTHTYPE_NOT_SUPPORTED               ErrorCode = 7   // Specified authentication method is not supported
	ERR_HUB_NOT_FOUND                        ErrorCode = 8   // The HUB does not exist
	ERR_AUTH_FAILED                          ErrorCode = 9   // Authentication failure
	ERR_HUB_STOPPING                         ErrorCode = 10  // HUB is stopped
	ERR_SESSION_REMOVED                      ErrorCode = 11  // Session has been deleted
	ERR_ACCESS_DENIED                        ErrorCode = 12  // Access denied
	ERR_SESSION_TIMEOUT                      ErrorCode = 13  // Session times out
	ERR_INVALID_PROTOCOL                     ErrorCode = 14  // Protocol is invalid
	ERR_TOO_MANY_CONNECTION                  ErrorCode = 15  // Too many connections
	ERR_HUB_IS_BUSY                          ErrorCode = 16  // Too many sessions of the HUB
	ERR_PROXY_CONNECT_FAILED                 ErrorCode = 17  // Connection to the proxy server fails
	ERR_PROXY_ERROR                          ErrorCode = 18  // Proxy Error
	ERR_PROXY_AUTH_FAILED                    ErrorCode = 19  // Failed to authenticate on the proxy server
	ERR_TOO_MANY_USER_SESSION                ErrorCode = 20  // Too many sessions of the same user
	ERR_LICENSE_ERROR                        ErrorCode = 21  // License error
	ERR_DEVICE_DRIVER_ERROR                  ErrorCode = 22  // Device driver error
	ERR_INTERNAL_ERROR                       ErrorCode = 23  // Internal error
	ERR_SECURE_DEVICE_OPEN_FAILED            ErrorCode = 24  // The secure device cannot be opened
	ERR_SECURE_PIN_LOGIN_FAILED              ErrorCode = 25  // PIN code is incorrect
	ERR_SECURE_NO_CERT                       ErrorCode = 26  // Specified certificate is not stored
	ERR_SECURE_NO_PRIVATE_KEY                ErrorCode = 27  // Specified private key is not stored
	ERR_SECURE_CANT_WRITE                    ErrorCode = 28  // Write failure
	ERR_OBJECT_NOT_FOUND                     ErrorCode = 29  // Specified object can not be found
	ERR_VLAN_ALREADY_EXISTS                  ErrorCode = 30  // Virtual LAN card with the specified name already exists
	ERR_VLAN_INSTALL_ERROR                   ErrorCode = 31  // Specified virtual LAN card cannot be created
	ERR_VLAN_INVALID_NAME                    ErrorCode = 32  // Specified name of the virtual LAN card is invalid
	ERR_NOT_SUPPORTED                        ErrorCode = 33  // Unsupported
	ERR_ACCOUNT_ALREADY_EXISTS               ErrorCode = 34  // Account already exists
	ERR_ACCOUNT_ACTIVE                       ErrorCode = 35  // Account is operating
	ERR_ACCOUNT_NOT_FOUND                    ErrorCode = 36  // Specified account doesn't exist
	ERR_ACCOUNT_INACTIVE                     ErrorCode = 37  // Account is offline
	ERR_INVALID_PARAMETER                    ErrorCode = 38  // Parameter is invalid
	ERR_SECURE_DEVICE_ERROR                  ErrorCode = 39  // Error has occurred in the operation of the secure device
	ERR_NO_SECURE_DEVICE_SPECIFIED           ErrorCode = 40  // Secure device is not specified
	ERR_VLAN_IS_USED                         ErrorCode = 41  // Virtual LAN card in use by account
	ERR_VLAN_FOR_ACCOUNT_NOT_FOUND           ErrorCode = 42  // Virtual LAN card of the account can not be found
	ERR_VLAN_FOR_ACCOUNT_USED                ErrorCode = 43  // Virtual LAN card of the account is already in use
	ERR_VLAN_FOR_ACCOUNT_DISABLED            ErrorCode = 44  // Virtual LAN card of the account is disabled
	ERR_INVALID_VALUE                        ErrorCode = 45  // Value is invalid
	ERR_NOT_FARM_CONTROLLER                  ErrorCode = 46  // Not a farm controller
	ERR_TRYING_TO_CONNECT                    ErrorCode = 47  // Attempting to connect
	ERR_CONNECT_TO_FARM_CONTROLLER           ErrorCode = 48  // Failed to connect to the farm controller
	ERR_COULD_NOT_HOST_HUB_ON_FARM           ErrorCode = 49  // A virtual HUB on farm could not be created
	ERR_FARM_MEMBER_HUB_ADMIN                ErrorCode = 50  // HUB cannot be managed on a farm member
	ERR_NULL_PASSWORD_LOCAL_ONLY             ErrorCode = 51  // Accepting only local connections for an empty password
	ERR_NOT_ENOUGH_RIGHT                     ErrorCode = 52  // Right is insufficient
	ERR_LISTENER_NOT_FOUND                   ErrorCode = 53  // Listener can not be found
	ERR_LISTENER_ALREADY_EXISTS              ErrorCode = 54  // Listener already exists
	ERR_NOT_FARM_MEMBER                      ErrorCode = 55  // Not a farm member
	ERR_CIPHER_NOT_SUPPORTED                 ErrorCode = 56  // Encryption algorithm is not supported
	ERR_HUB_ALREADY_EXISTS                   ErrorCode = 57  // HUB already exists
	ERR_TOO_MANY_HUBS                        ErrorCode = 58  // Too many HUBs
	ERR_LINK_ALREADY_EXISTS                  ErrorCode = 59  // Link already exists
	ERR_LINK_CANT_CREATE_ON_FARM             ErrorCode = 60  // The link can not be created on the server farm
	ERR_LINK_IS_OFFLINE                      ErrorCode = 61  // Link is off-line
	ERR_TOO_MANY_ACCESS_LIST                 ErrorCode = 62  // Too many access list
	ERR_TOO_MANY_USER                        ErrorCode = 63  // Too many users
	ERR_TOO_MANY_GROUP                       ErrorCode = 64  // Too many Groups
	ERR_GROUP_NOT_FOUND                      ErrorCode = 65  // Group can not be found
	ERR_USER_ALREADY_EXISTS                  ErrorCode = 66  // User already exists
	ERR_GROUP_ALREADY_EXISTS                 ErrorCode = 67  // Group already exists
	ERR_USER_AUTHTYPE_NOT_PASSWORD           ErrorCode = 68  // Authentication method of the user is not a password authentication
	ERR_OLD_PASSWORD_WRONG                   ErrorCode = 69  // The user does not exist or the old password is wrong
	ERR_LINK_CANT_DISCONNECT                 ErrorCode = 73  // Cascade session cannot be disconnected
	ERR_ACCOUNT_NOT_PRESENT                  ErrorCode = 74  // Not completed configure the connection to the VPN server
	ERR_ALREADY_ONLINE                       ErrorCode = 75  // It is already online
	ERR_OFFLINE                              ErrorCode = 76  // It is offline
	ERR_NOT_RSA_1024                         ErrorCode = 77  // The certificate is not RSA 1024bit
	ERR_SNAT_CANT_DISCONNECT                 ErrorCode = 78  // SecureNAT session cannot be disconnected
	ERR_SNAT_NEED_STANDALONE                 ErrorCode = 79  // SecureNAT works only in stand-alone HUB
	ERR_SNAT_NOT_RUNNING                     ErrorCode = 80  // SecureNAT function is not working
	ERR_SE_VPN_BLOCK                         ErrorCode = 81  // Stopped by PacketiX VPN Block
	ERR_BRIDGE_CANT_DISCONNECT               ErrorCode = 82  // Bridge session can not be disconnected
	ERR_LOCAL_BRIDGE_STOPPING                ErrorCode = 83  // Bridge function is stopped
	ERR_LOCAL_BRIDGE_UNSUPPORTED             ErrorCode = 84  // Bridge feature is not supported
	ERR_CERT_NOT_TRUSTED                     ErrorCode = 85  // Certificate of the destination server can not be trusted
	ERR_PRODUCT_CODE_INVALID                 ErrorCode = 86  // Product code is different
	ERR_VERSION_INVALID                      ErrorCode = 87  // Version is different
	ERR_CAPTURE_DEVICE_ADD_ERROR             ErrorCode = 88  // Adding capture device failure
	ERR_VPN_CODE_INVALID                     ErrorCode = 89  // VPN code is different
	ERR_CAPTURE_NOT_FOUND                    ErrorCode = 90  // Capture device can not be found
	ERR_LAYER3_CANT_DISCONNECT               ErrorCode = 91  // Layer-3 session cannot be disconnected
	ERR_LAYER3_SW_EXISTS                     ErrorCode = 92  // L3 switch of the same already exists
	ERR_LAYER3_SW_NOT_FOUND                  ErrorCode = 93  // Layer-3 switch can not be found
	ERR_INVALID_NAME                         ErrorCode = 94  // Name is invalid
	ERR_LAYER3_IF_ADD_FAILED                 ErrorCode = 95  // Failed to add interface
	ERR_LAYER3_IF_DEL_FAILED                 ErrorCode = 96  // Failed to delete the interface
	ERR_LAYER3_IF_EXISTS                     ErrorCode = 97  // Interface that you specified already exists
	ERR_LAYER3_TABLE_ADD_FAILED              ErrorCode = 98  // Failed to add routing table
	ERR_LAYER3_TABLE_DEL_FAILED              ErrorCode = 99  // Failed to delete the routing table
	ERR_LAYER3_TABLE_EXISTS                  ErrorCode = 100 // Routing table entry that you specified already exists
	ERR_BAD_CLOCK                            ErrorCode = 101 // Time is queer
	ERR_LAYER3_CANT_START_SWITCH             ErrorCode = 102 // The Virtual Layer 3 Switch can not be started
	ERR_CLIENT_LICENSE_NOT_ENOUGH            ErrorCode = 103 // Client connection licenses shortage
	ERR_BRIDGE_LICENSE_NOT_ENOUGH            ErrorCode = 104 // Bridge connection licenses shortage
	ERR_SERVER_CANT_ACCEPT                   ErrorCode = 105 // Not Accept on the technical issues
	ERR_SERVER_CERT_EXPIRES                  ErrorCode = 106 // Destination VPN server has expired
	ERR_MONITOR_MODE_DENIED                  ErrorCode = 107 // Monitor port mode was rejected
	ERR_BRIDGE_MODE_DENIED                   ErrorCode = 108 // Bridge-mode or Routing-mode was rejected
	ERR_IP_ADDRESS_DENIED                    ErrorCode = 109 // Client IP address is denied
	ERR_TOO_MANT_ITEMS                       ErrorCode = 110 // Too many items
	ERR_MEMORY_NOT_ENOUGH                    ErrorCode = 111 // Out of memory
	ERR_OBJECT_EXISTS                        ErrorCode = 112 // Object already exists
	ERR_FATAL                                ErrorCode = 113 // A fatal error occurred
	ERR_SERVER_LICENSE_FAILED                ErrorCode = 114 // License violation has occurred on the server side
	ERR_SERVER_INTERNET_FAILED               ErrorCode = 115 // Server side is not connected to the Internet
	ERR_CLIENT_LICENSE_FAILED                ErrorCode = 116 // License violation occurs on the client side
	ERR_BAD_COMMAND_OR_PARAM                 ErrorCode = 117 // Command or parameter is invalid
	ERR_INVALID_LICENSE_KEY                  ErrorCode = 118 // License key is invalid
	ERR_NO_VPN_SERVER_LICENSE                ErrorCode = 119 // There is no valid license for the VPN Server
	ERR_NO_VPN_CLUSTER_LICENSE               ErrorCode = 120 // There is no cluster license
	ERR_NOT_ADMINPACK_SERVER                 ErrorCode = 121 // Not trying to connect to a server with the Administrator Pack license
	ERR_NOT_ADMINPACK_SERVER_NET             ErrorCode = 122 // Not trying to connect to a server with the Administrator Pack license (for .NET)
	ERR_BETA_EXPIRES                         ErrorCode = 123 // Destination Beta VPN Server has expired
	ERR_BRANDED_C_TO_S                       ErrorCode = 124 // Branding string of connection limit is different (Authentication on the server side)
	ERR_BRANDED_C_FROM_S                     ErrorCode = 125 // Branding string of connection limit is different (Authentication for client-side)
	ERR_AUTO_DISCONNECTED                    ErrorCode = 126 // VPN session is disconnected for a certain period of time has elapsed
	ERR_CLIENT_ID_REQUIRED                   ErrorCode = 127 // Client ID does not match
	ERR_TOO_MANY_USERS_CREATED               ErrorCode = 128 // Too many created users
	ERR_SUBSCRIPTION_IS_OLDER                ErrorCode = 129 // Subscription expiration date Is earlier than the build date of the VPN Server
	ERR_ILLEGAL_TRIAL_VERSION                ErrorCode = 130 // Many trial license is used continuously
	ERR_NAT_T_TWO_OR_MORE                    ErrorCode = 131 // There are multiple servers in the back of a global IP address in the NAT-T connection
	ERR_DUPLICATE_DDNS_KEY                   ErrorCode = 132 // DDNS host key duplicate
	ERR_DDNS_HOSTNAME_EXISTS                 ErrorCode = 133 // Specified DDNS host name already exists
	ERR_DDNS_HOSTNAME_INVALID_CHAR           ErrorCode = 134 // Characters that can not be used for the host name is included
	ERR_DDNS_HOSTNAME_TOO_LONG               ErrorCode = 135 // Host name is too long
	ERR_DDNS_HOSTNAME_IS_EMPTY               ErrorCode = 136 // Host name is not specified
	ERR_DDNS_HOSTNAME_TOO_SHORT              ErrorCode = 137 // Host name is too short
	ERR_MSCHAP2_PASSWORD_NEED_RESET          ErrorCode = 138 // Necessary that password is changed
	ERR_DDNS_DISCONNECTED                    ErrorCode = 139 // Communication to the dynamic DNS server is disconnected
	ERR_SPECIAL_LISTENER_ICMP_ERROR          ErrorCode = 140 // The ICMP socket can not be opened
	ERR_SPECIAL_LISTENER_DNS_ERROR           ErrorCode = 141 // Socket for DNS port can not be opened
	ERR_OPENVPN_IS_NOT_ENABLED               ErrorCode = 142 // OpenVPN server feature is not enabled
	ERR_NOT_SUPPORTED_AUTH_ON_OPENSOURCE     ErrorCode = 143 // It is the type of user authentication that are not supported in the open source version
	ERR_VPNGATE                              ErrorCode = 144 // Operation on VPN Gate Server is not available
	ERR_VPNGATE_CLIENT                       ErrorCode = 145 // Operation on VPN Gate Client is not available
	ERR_VPNGATE_INCLIENT_CANT_STOP           ErrorCode = 146 // Can not be stopped if operating within VPN Client mode
	ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE ErrorCode = 147 // It is a feature that is not supported in the open source version
	ERR_SUSPENDING                           ErrorCode = 148 // System is suspending
)

// Cedar structure
type Cedar struct {
	ClientId uint32
}

// NewCedar new Cedar
func NewCedar() *Cedar {
	c := &Cedar{
		ClientId: 123, // https://github.com/SoftEtherVPN/SoftEtherVPN/blob/master/src/bin/hamcore/strtable_en.stb
	}

	return c
}

// RPCWinVer RPC Windows version
type RPCWinVer struct {
	IsWindows   bool
	IsNT        bool
	IsServer    bool
	IsBeta      bool
	VerMajor    uint32
	VerMinor    uint32
	Build       uint32
	ServicePack uint32
	Title       string
}

// GetWinVer get win ver
func GetWinVer() RPCWinVer {
	return RPCWinVer{
		IsWindows: runtime.GOOS == "windows",
		IsNT:      runtime.GOOS == "windows",
		Title:     runtime.GOOS + "/" + runtime.GOARCH,
	}
}
