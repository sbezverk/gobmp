compile-validator:
	CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator ./validator.go

compile-validator-mac-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator.mac ./validator.go

compile-validator-mac-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator.mac.arm64 ./validator.go
