build:
	go build -o bin/main app/gopherbook/main.go

clean:
	rm -rf watch etc library cache
