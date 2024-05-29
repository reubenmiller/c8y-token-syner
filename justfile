set dotenv-load

start:
    go run ./cmd/main/main.go

build:
    goreleaser release --snapshot --clean
    ./build/microservice.sh pack --name c8y-token-syner
