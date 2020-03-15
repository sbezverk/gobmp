module gobmp

go 1.13

require (
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/sbezverk/gobmp/pkg/bmp/srv6 v0.0.0-00010101000000-000000000000
	github.com/sbezverk/gobmp/pkg/internal v0.0.0-00010101000000-000000000000 // indirect
)

replace (
	github.com/sbezverk/gobmp/pkg/bmp/srv6 => ./pkg/bmp/srv6
	github.com/sbezverk/gobmp/pkg/internal => ./pkg/internal
)
