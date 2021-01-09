package cedar

import "go-softether/mayaqua"

// OutRpcNodeInfo outout rpc node info
func OutRpcNodeInfo(p *mayaqua.Pack, t NodeInfo) {
	p.AddStr("ClientProductName", t.ClientProductName)
	p.AddStr("ServerProductName", t.ServerProductName)
	p.AddStr("ClientOsName", t.ClientOsName)
	p.AddStr("ClientOsVer", t.ClientOsVer)
	p.AddStr("ClientOsProductId", t.ClientOsProductId)
	p.AddStr("ClientHostname", t.ClientHostname)
	p.AddStr("ServerHostname", t.ServerHostname)
	p.AddStr("ProxyHostname", t.ProxyHostname)
	p.AddStr("HubName", t.HubName)
	p.AddData("UniqueId", t.UniqueId[:])

	p.AddInt("ClientProductVer", t.ClientProductVer)
	p.AddInt("ClientProductBuild", t.ClientProductBuild)
	p.AddInt("ServerProductVer", t.ServerProductVer)
	p.AddInt("ServerProductBuild", t.ServerProductBuild)
	p.AddIp32("ClientIpAddress", t.ClientIpAddress)
	p.AddData("ClientIpAddress6", t.ClientIpAddress6[:])
	p.AddInt("ClientPort", t.ClientPort)
	p.AddIp32("ServerIpAddress", t.ServerIpAddress)
	p.AddData("ServerIpAddress6", t.ServerIpAddress6[:])
	p.AddInt("ServerPort2", t.ServerPort)
	p.AddIp32("ProxyIpAddress", t.ProxyIpAddress)
	p.AddData("ProxyIpAddress6", t.ProxyIpAddress6[:])
	p.AddInt("ProxyPort", t.ProxyPort)
}

// OutRpcWinVer output rpc windows version
func OutRpcWinVer(p *mayaqua.Pack, t RPCWinVer) {
	p.AddBool("V_IsWindows", t.IsWindows)
	p.AddBool("V_IsNT", t.IsNT)
	p.AddBool("V_IsServer", t.IsServer)
	p.AddBool("V_IsBeta", t.IsBeta)
	p.AddInt("V_VerMajor", t.VerMajor)
	p.AddInt("V_VerMinor", t.VerMinor)
	p.AddInt("V_Build", t.Build)
	p.AddInt("V_ServicePack", t.ServicePack)
	p.AddStr("V_Title", t.Title)
}
