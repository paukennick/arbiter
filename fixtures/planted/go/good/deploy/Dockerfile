# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
ARG RUNTIME
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY . .
RUN go install golang.org/x/tools/cmd/stringer@v0.24.0
RUN curl -fsSLo /tmp/install.sh https://raw.githubusercontent.com/golangci/golangci-lint/v1.61.0/install.sh \
    && echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  /tmp/install.sh" | sha256sum -c - \
    && sh /tmp/install.sh -b /usr/local/bin
RUN go build -o /out/app ./...

FROM build AS test
RUN go test ./...

FROM $RUNTIME AS custom
FROM alpine:3.20@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
COPY --from=ghcr.io/tarampampam/curl:8.10.1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef /bin/curl /bin/curl
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
