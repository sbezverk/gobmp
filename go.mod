module gobmp

go 1.13

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/sbezverk/gobmp/pkg/bgp v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/bmp v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/dumper v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/gobmpsrv v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/kafka v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/message v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/parser v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/pub v0.0.0-20200420214652-390271d2c7c6
	github.com/segmentio/kafka-go v0.3.5 // indirect
)

replace (
	github.com/sbezverk/gobmp => ./
	github.com/sbezverk/gobmp/pkg/base => ./pkg/base
	github.com/sbezverk/gobmp/pkg/bgp => ./pkg/bgp
	github.com/sbezverk/gobmp/pkg/bgpls => ./pkg/bgpls
	github.com/sbezverk/gobmp/pkg/bmp => ./pkg/bmp
	github.com/sbezverk/gobmp/pkg/dumper => ./pkg/dumper
	github.com/sbezverk/gobmp/pkg/evpn => ./pkg/evpn
	github.com/sbezverk/gobmp/pkg/gobmpsrv => ./pkg/gobmpsrv
	github.com/sbezverk/gobmp/pkg/kafka => ./pkg/kafka
	github.com/sbezverk/gobmp/pkg/l3vpn => ./pkg/l3vpn
	github.com/sbezverk/gobmp/pkg/ls => ./pkg/ls
	github.com/sbezverk/gobmp/pkg/message => ./pkg/message
	github.com/sbezverk/gobmp/pkg/parser => ./pkg/parser
	github.com/sbezverk/gobmp/pkg/prefixsid => ./pkg/prefixsid
	github.com/sbezverk/gobmp/pkg/pub => ./pkg/pub
	github.com/sbezverk/gobmp/pkg/sr => ./pkg/sr
	github.com/sbezverk/gobmp/pkg/srv6 => ./pkg/srv6
	github.com/sbezverk/gobmp/pkg/tools => ./pkg/tools
	github.com/sbezverk/gobmp/pkg/unicast => ./pkg/unicast
)
