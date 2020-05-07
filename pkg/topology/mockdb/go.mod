module github.com/sbezverk/gobmp/pkg/topology/mockdb

go 1.14

replace (
	github.com/sbezverk/gobmp/pkg/topology/dbclient => ../dbclient
	github.com/sbezverk/gobmp/pkg/topology/kafkamessenger => ../kafkamessenger
	github.com/sbezverk/gobmp/pkg/topology/messenger => ../messenger
	github.com/sbezverk/gobmp/pkg/topology/mockdb => ../mockdb
	github.com/sbezverk/gobmp/pkg/topology/mockmessenger => ../mockmessenger
)
require (
        github.com/sbezverk/gobmp/pkg/base v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/bgp v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/bmp v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/gobmpsrv v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/kafka v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/ls v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/message v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/parser v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/pub v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/sr v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-20200506222259-57521a093f5d
        github.com/sbezverk/gobmp/pkg/tools v0.0.0-20200506222259-57521a093f5d
)
