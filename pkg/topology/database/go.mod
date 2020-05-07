module github.com/sbezverk/gobmp/pkg/topology/database

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
	github.com/arangodb/go-driver v0.0.0-20200403100147-ca5dd87ffe93
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
)
