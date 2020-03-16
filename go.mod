module gobmp

go 1.13

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/sbezverk/gobmp/pkg/base v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/bgp v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/bmp v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/internal v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/ls v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/sr v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-00010101000000-000000000000
)

replace (
	github.com/sbezverk/gobmp => ./
	github.com/sbezverk/gobmp/pkg/base => ./pkg/base
	github.com/sbezverk/gobmp/pkg/bgp => ./pkg/bgp
	github.com/sbezverk/gobmp/pkg/bgpls => ./pkg/bgpls
	github.com/sbezverk/gobmp/pkg/bmp => ./pkg/bmp
	github.com/sbezverk/gobmp/pkg/internal => ./pkg/internal
	github.com/sbezverk/gobmp/pkg/ls => ./pkg/ls
	github.com/sbezverk/gobmp/pkg/sr => ./pkg/sr
	github.com/sbezverk/gobmp/pkg/srv6 => ./pkg/srv6
)
