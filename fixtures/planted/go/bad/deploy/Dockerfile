# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22
ARG RUNTIME
FROM golang:${GO_VERSION} AS build # expect: arbiter/supply.unpinned-container-image
WORKDIR /src
COPY . .
RUN go install golang.org/x/tools/cmd/stringer@latest # expect: arbiter/supply.unpinned-install-in-build
RUN curl -fsSL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b /usr/local/bin # expect: arbiter/supply.remote-script-piped
RUN go build -o /out/app ./...

FROM build AS test
RUN go test ./...

FROM $RUNTIME AS custom
FROM alpine # expect: arbiter/supply.unpinned-container-image
COPY --from=ghcr.io/tarampampam/curl:latest /bin/curl /bin/curl # expect: arbiter/supply.unpinned-container-image
COPY --from=build /out/app /app
ENTRYPOINT ["/app"]
