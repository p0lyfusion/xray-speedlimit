FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/xray-speedlimit ./cmd/xray-speedlimit

FROM alpine:3.24

RUN apk add --no-cache ca-certificates iproute2 nftables ethtool

COPY --from=builder /out/xray-speedlimit /usr/local/bin/xray-speedlimit

EXPOSE 7070
ENTRYPOINT ["/usr/local/bin/xray-speedlimit"]
