compile-gobmp:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/gobmp ./gobmp.go

compile-gobmp-mac-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/gobmp.mac.arm64 ./gobmp.go

compile-gobmp-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/gobmp.linux.arm64 ./gobmp.go

compile-gobmp-mac-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/gobmp.mac.amd64 ./gobmp.go
