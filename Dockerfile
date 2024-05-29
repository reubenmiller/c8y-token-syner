FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /go/bin
COPY ./dist/c8y-token-syner_linux_amd64_v1/c8y-token-syner ./app
COPY config/application.production.properties ./application.properties
CMD ["./app"]
