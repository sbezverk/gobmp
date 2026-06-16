compile-validator_v2:
	CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator_v2 ./validator_v2.go ./validator_types.go

compile-validator_v2-mac-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator_v2.mac ./validator_v2.go ./validator_types.go

compile-validator_v2-mac-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator_v2.mac.arm64 ./validator_v2.go ./validator_types.go
