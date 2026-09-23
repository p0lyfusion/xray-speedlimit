FROM golang:1.26-alpine AS builder

RUN apk add --no-cache clang llvm musl-dev git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go generate ./... && \
    CGO_ENABLED=0 go build -o /out/ebpf-speedlimit ./cmd/ebpf-speedlimit

FROM alpine:3.24

RUN apk add --no-cache ca-certificates iproute2 nftables ethtool

COPY --from=builder /out/ebpf-speedlimit /usr/local/bin/ebpf-speedlimit

EXPOSE 7070
ENTRYPOINT ["/usr/local/bin/ebpf-speedlimit"]
