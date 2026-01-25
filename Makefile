build:
	go build -o bin/main ./app/gopherbook

clean:
	rm -rf watch etc library cache binaries releases
