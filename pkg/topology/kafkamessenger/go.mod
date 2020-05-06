module github.com/sbezverk/gobmp/pkg/topology/kafkamessenger

go 1.14

replace (
	github.com/sbezverk/gobmp/pkg/topology/dbclient => ../dbclient
	github.com/sbezverk/gobmp/pkg/topology/processor => ../processor
	github.com/sbezverk/gobmp/pkg/topology/kafkamessenger => ../kafkamessenger
	github.com/sbezverk/gobmp/pkg/topology/messenger => ../messenger
	github.com/sbezverk/gobmp/pkg/topology/mockdb => ../mockdb
	github.com/sbezverk/gobmp/pkg/topology/mockmessenger => ../mockmessenger
)
require (
github.com/sbezverk/gobmp/pkg/prefixsid v0.0.0-20200505182324-42790423b6c7
github.com/sbezverk/gobmp/pkg/base v0.0.0-20200505182324-42790423b6c7
)
