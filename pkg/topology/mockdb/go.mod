module mockdb

go 1.14

replace (
	github.com/sbezverk/gobmp/pkg/topology/dbclient => ../dbclient
	github.com/sbezverk/gobmp/pkg/topology/kafkamessenger => ../kafkamessenger
	github.com/sbezverk/gobmp/pkg/topology/messenger => ../messenger
	github.com/sbezverk/gobmp/pkg/topology/mockdb => ../mockdb
	github.com/sbezverk/gobmp/pkg/topology/mockmessenger => ../mockmessenger
)