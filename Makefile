build:
	go build -o bin/main ./app/gopherbook

build-for-guix:
	guix shell -m guix-manifest/manifest.scm -- bash -c \
                'CGO_CFLAGS="-I$$GUIX_ENVIRONMENT/include" \
                CGO_LDFLAGS="-L$$GUIX_ENVIRONMENT/lib" \
                go build -v -tags desktop \
                -ldflags="-s -w" \
                -trimpath -gcflags="-l=4" -asmflags=-trimpath \
                -o binaries/gopherbook-desktop-linux-guix \
                ./app/gopherbook'

build-in-podman:
	bash ./scripts-bash/building-only/build-release.sh

clean:
	rm -rf watch etc library cache binaries releases bin

