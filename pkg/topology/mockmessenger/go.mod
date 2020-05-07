module github.com/sbezverk/gobmp/pkg/topology/mockmessenger

go 1.14

replace (
	github.com/sbezverk/gobmp/pkg/base => github.com/sbezverk/gobmp/pkg/base v0.0.0-20200507012955-3207954567bb
	github.com/sbezverk/gobmp/pkg/bgp => github.com/sbezverk/gobmp/pkg/bgp v0.0.0-20200507012955-3207954567bb
	github.com/sbezverk/gobmp/pkg/bgpls => github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-20200507012955-3207954567bb
	github.com/sbezverk/gobmp/pkg/bmp => github.com/sbezverk/gobmp/pkg/bmp v0.0.0-20200507012955-3207954567bb
	github.com/sbezverk/gobmp/pkg/prefixsid => github.com/sbezverk/gobmp/pkg/prefixsid v0.0.0-20200507012955-3207954567bb
	github.com/sbezverk/gobmp/pkg/srv6 => github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-20200507012955-3207954567bb
)

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/sbezverk/gobmp/pkg/base v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/bgp v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/bmp v0.0.0-20200507012955-3207954567bb
	github.com/sbezverk/gobmp/pkg/evpn v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/l3vpn v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/ls v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/message v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/prefixsid v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/pub v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/sr v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/tools v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/topology/dbclient v0.0.0-20200507012955-3207954567bb // indirect
	github.com/sbezverk/gobmp/pkg/topology/processor v0.0.0-20200507012955-3207954567bb
	github.com/sbezverk/gobmp/pkg/unicast v0.0.0-20200507012955-3207954567bb // indirect
)
