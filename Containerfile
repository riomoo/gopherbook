# Build stage
#
# Pin: to update this digest, run:
#   podman inspect --format='{{index .RepoDigests 0}}' golang:alpine
#   docker inspect --format='{{index .RepoDigests 0}}' golang:alpine
# Then replace it below.
FROM docker.io/library/golang@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

# Pin APK package versions.
# To refresh versions after an intentional update:
#podman run --rm docker.io/library/golang@sha256: \
#  sh -c "apk update -q && apk search -x musl-dev gcc wget xz git" \
#  | sort \
#  | awk 'match($0, /^(.*)-([0-9]+\..*)$/, a) {printf "    %s=%s \\\n", a[1], a[2]}'
#docker run --rm docker.io/library/golang@sha256: \
#  sh -c "apk update -q && apk search -x musl-dev gcc wget xz git" \
#  | sort \
#  | awk 'match($0, /^(.*)-([0-9]+\..*)$/, a) {printf "    %s=%s \\\n", a[1], a[2]}'
RUN apk add --no-cache \
    gcc=15.2.0-r2 \
    git=2.52.0-r0 \
    musl-dev=1.2.5-r23 \
    wget=1.25.0-r2 \
    xz=5.8.3-r0

# Install UPX — pinned version + SHA256 verification.
# NOTE: --best is used intentionally. --ultra-brute is non-deterministic
# (it runs random compression trials) and produces different bytes each
# build, defeating reproducibility. --best is fully deterministic.
RUN wget -q https://github.com/upx/upx/releases/download/v5.1.1/upx-5.1.1-amd64_linux.tar.xz && \
    echo "1ff660454227861e00772f743f66b900072116b9dc24f6ee28b97cce88a7828a  upx-5.1.1-amd64_linux.tar.xz" | sha256sum -c - && \
    tar -xf upx-5.1.1-amd64_linux.tar.xz && \
    mv upx-5.1.1-amd64_linux/upx /usr/local/bin/upx && \
    rm -r upx-5.1.1-amd64_linux upx-5.1.1-amd64_linux.tar.xz

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
	-ldflags="-s -w -linkmode external -extldflags '-static'" \
	-trimpath -gcflags="-l=4" -asmflags=-trimpath \
	-o bin/main ./app/gopherbook
RUN upx --best --lzma --brute bin/main
RUN chmod +x bin/main

# Runtime image.
# IMPORTANT: pin alisterbase to a digest for full reproducibility, e.g.:
#   FROM git.jester-designs.com/riomoo/alisterbase@sha256:<digest>
# Get the digest with:
#   podman inspect --format='{{index .RepoDigests 0}}' git.jester-designs.com/riomoo/alisterbase:latest
#   docker inspect --format='{{index .RepoDigests 0}}' git.jester-designs.com/riomoo/alisterbase:latest
FROM git.jester-designs.com/riomoo/alisterbase@sha256:903b779f25bebc7d38d83b58b42cb349a214f789f76aa24e7c511aa9f0e180f0

WORKDIR /app

COPY --from=builder /app/bin/main ./bin/main

EXPOSE 8080
USER root:root
CMD ["./bin/main"]
