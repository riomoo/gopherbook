# Build stage
FROM golang:alpine AS builder
RUN apk add --no-cache \
    musl-dev \
    gcc \
    wget \
    xz \
    git

RUN wget https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-amd64_linux.tar.xz && \
    tar -xf upx-5.0.2-amd64_linux.tar.xz && \
    mv upx-5.0.2-amd64_linux/upx /usr/local/bin/upx && \
    rm -r upx-5.0.2-amd64_linux upx-5.0.2-amd64_linux.tar.xz

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

# musl_compat.c (in app/gopherbook/) provides stub implementations of glibc
# _FORTIFY_SOURCE symbols (__memcpy_chk, __snprintf_chk, etc.) that musl lacks.
# This satisfies the linker when statically linking vegidio/avif-go's prebuilt
# glibc-compiled .a files without needing to change the builder base image.
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -a \
    -ldflags="-s -w -linkmode external -extldflags '-static' -X main.GOMEMLIMIT=512MiB -X runtime.defaultGOGC=50" \
    -trimpath \
    -o bin/main ./app/gopherbook
RUN upx --best --ultra-brute bin/main
RUN chmod +x bin/main

FROM git.jester-designs.com/riomoo/alisterbase:latest

WORKDIR /app

COPY --from=builder /app/bin/main ./bin/main

EXPOSE 8080
USER root:root
CMD ["./bin/main"]
