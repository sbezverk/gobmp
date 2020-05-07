module github.com/sbezverk/gobmp/pkg/topology/arangodb

go 1.14

replace (
	github.com/sbezverk/gobmp/pkg/topology/dbclient => ../dbclient
	github.com/sbezverk/gobmp/pkg/topology/kafkamessenger => ../kafkamessenger
	github.com/sbezverk/gobmp/pkg/topology/messenger => ../messenger
	github.com/sbezverk/gobmp/pkg/topology/mockdb => ../mockdb
	github.com/sbezverk/gobmp/pkg/topology/mockmessenger => ../mockmessenger
)

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/sbezverk/gobmp/pkg/base v0.0.0-20200506222259-57521a093f5d // indirect
	github.com/sbezverk/gobmp/pkg/bgp v0.0.0-20200506222259-57521a093f5d // indirect
	github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-20200506222259-57521a093f5d // indirect
	github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-20200506222259-57521a093f5d // indirect
	github.com/sbezverk/gobmp/pkg/topology/dbclient v0.0.0-20200506222259-57521a093f5d // indirect
)
