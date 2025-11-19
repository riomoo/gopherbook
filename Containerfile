# Build stage
FROM golang:bookworm AS builder

# Install UPX
RUN apt-get update && apt-get install -y wget xz-utils && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-amd64_linux.tar.xz
RUN tar -xf upx-5.0.2-amd64_linux.tar.xz && mv upx-5.0.2-amd64_linux/upx /usr/local/bin/upx && rm -r upx-5.0.2-amd64_linux upx-5.0.2-amd64_linux.tar.xz

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN mkdir -p /var/sockets
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags="-s -w -extldflags '-static' -X main.GOMEMLIMIT=256MiB -X runtime.defaultGOGC=50" -trimpath -gcflags="-l=4" -asmflags=-trimpath -o bin/main app/gopherbook/main.go
RUN upx --best --ultra-brute bin/main
RUN chmod +x bin/main

# Final stage with Chainguard static
FROM cgr.dev/chainguard/static:latest
WORKDIR /app

# Copy the binary
COPY --from=builder /app/bin/main ./bin/main

# Create directories that will be mounted and set ownership
EXPOSE 8080
USER root:root
CMD ["./bin/main"]
