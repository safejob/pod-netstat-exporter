FROM --platform=$BUILDPLATFORM golang:1.22.2

ARG BUILDPLATFORM
ARG TARGETARCH
ARG TARGETOS

ENV GO111MODULE=on
WORKDIR /go/src/github.com/eegseth/pod-netstat-exporter

# Cache dependencies
COPY go.mod .
COPY go.sum .
RUN go get github.com/eegseth/pod-netstat-exporter
RUN go mod download

COPY . /go/src/github.com/eegseth/pod-netstat-exporter/

RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} GOOS=${TARGETOS} go build -o ./pod-netstat-exporter -a -installsuffix cgo .

FROM alpine:3.11
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=0 /go/src/github.com/eegseth/pod-netstat-exporter/pod-netstat-exporter /root/pod-netstat-exporter
