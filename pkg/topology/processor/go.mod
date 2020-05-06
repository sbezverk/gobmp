module github.com/sbezverk/gobmp/pkg/topology/processor

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
        github.com/sbezverk/gobmp/pkg/topology/dbclient v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/base v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/bgpls v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/evpn v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/l3vpn v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/ls v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/prefixsid v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/sr v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/srv6 v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/tools v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/unicast v0.0.0-20200506204513-5d750be958f3
        github.com/sbezverk/gobmp/pkg/message v0.0.0-20200506204513-5d750be958f3
)
