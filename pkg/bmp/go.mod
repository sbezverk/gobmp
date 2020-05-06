module github.com/sbezverk/gobmp/pkg/bmp

go 1.13

replace (
	github.com/sbezverk/gobmp/pkg/base => ../base
	github.com/sbezverk/gobmp/pkg/bgp => ../bgp
	github.com/sbezverk/gobmp/pkg/bgpls => ../bgpls
	github.com/sbezverk/gobmp/pkg/bmp => ../bmp
	github.com/sbezverk/gobmp/pkg/gobmpsrv => ../gobmpsrv
	github.com/sbezverk/gobmp/pkg/kafka => ../kafka
	github.com/sbezverk/gobmp/pkg/ls => ../ls
	github.com/sbezverk/gobmp/pkg/message => ../message
	github.com/sbezverk/gobmp/pkg/parser => ../parser
	github.com/sbezverk/gobmp/pkg/pub => ../pub
	github.com/sbezverk/gobmp/pkg/sr => ../sr
	github.com/sbezverk/gobmp/pkg/srv6 => ../srv6
	github.com/sbezverk/gobmp/pkg/tools => ../tools
)

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/sbezverk/gobmp/pkg/base v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/bgp v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/evpn v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/l3vpn v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/ls v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/prefixsid v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/sr v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/tools v0.0.0-20200506204513-5d750be958f3
	github.com/sbezverk/gobmp/pkg/unicast v0.0.0-20200506204513-5d750be958f3
)
