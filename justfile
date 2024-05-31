set dotenv-load

start:
    go run ./cmd/main/main.go

build:
    goreleaser release --snapshot --clean
    ./build/microservice.sh pack --name c8y-token-syner --manifest cumulocity.syner.json --dockerfile syner.dockerfile
    ./build/microservice.sh pack --name c8y-token-shared --manifest cumulocity.shared.json --dockerfile shared.dockerfile
