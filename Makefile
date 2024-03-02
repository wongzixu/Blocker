build:
	@go build -o bin/blocker

run: build
	@./bin/docker

test:
	@go test -v ./...

echo:
	@echo "Hello World"

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	--go-grpc_out=. --go-grpc_opt=paths=source_relative \
	proto/types.proto

.PHONY: proto