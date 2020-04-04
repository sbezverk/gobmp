module topology

go 1.14

replace (
	github.com/sbezverk/gobmp/pkg/topology/arangodb => ../../pkg/topology/arangodb
	github.com/sbezverk/gobmp/pkg/topology/dbclient => ../../pkg/topology/dbclient
	github.com/sbezverk/gobmp/pkg/topology/kafkamessenger => ../../pkg/topology/kafkamessenger
	github.com/sbezverk/gobmp/pkg/topology/messenger => ../../pkg/topology/messenger
	github.com/sbezverk/gobmp/pkg/topology/mockdb => ../../pkg/topology/mockdb
	github.com/sbezverk/gobmp/pkg/topology/mockmessenger => ../../pkg/topology/mockmessenger
	github.com/sbezverk/gobmp/pkg/topology/processor => ../../pkg/topology/processor
)

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/sbezverk/gobmp/pkg/topology/arangodb v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/topology/dbclient v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/topology/kafkamessenger v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/topology/messenger v0.0.0-00010101000000-000000000000 // indirect
	github.com/sbezverk/gobmp/pkg/topology/processor v0.0.0-00010101000000-000000000000 // indirect
)
