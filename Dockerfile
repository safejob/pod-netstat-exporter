FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.22.2

ARG BUILDPLATFORM
ARG TARGETARCH=amd64
ARG TARGETOS=linux

ENV GO111MODULE=on
WORKDIR /go/src/github.com/eegseth/pod-netstat-exporter

# Cache dependencies
ENV GOPROXY=https://goproxy.cn
COPY go.mod .
COPY go.sum .

RUN go mod download


COPY . /go/src/github.com/eegseth/pod-netstat-exporter/

RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} GOOS=${TARGETOS} go build -o ./pod-netstat-exporter -a -installsuffix cgo .

#FROM --platform=${BUILDPLATFORM:-linux/amd64} alpine:3.15.5
FROM registry.cn-hangzhou.aliyuncs.com/keruyun/alpine:3.15.5
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=0 /go/src/github.com/eegseth/pod-netstat-exporter/pod-netstat-exporter /root/pod-netstat-exporter
