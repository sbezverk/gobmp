module github.com/sbezverk/gobmp/pkg/parser

go 1.14

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/sbezverk/gobmp/pkg/base v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/bgp v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/bmp v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/tools v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/ls v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/sr v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-00010101000000-000000000000 // indirect
)

replace (
	github.com/sbezverk/gobmp/pkg/base => ../base
	github.com/sbezverk/gobmp/pkg/bgp => ../bgp
	github.com/sbezverk/gobmp/pkg/bgpls => ../bgpls
	github.com/sbezverk/gobmp/pkg/bmp => ../bmp
	github.com/sbezverk/gobmp/pkg/tools => ../tools
	github.com/sbezverk/gobmp/pkg/ls => ../ls
	github.com/sbezverk/gobmp/pkg/sr => ../sr
	github.com/sbezverk/gobmp/pkg/srv6 => ../srv6
)
