mini:
	go build ./cmd/fuss; strip fuss; upx fuss

build:
	go build ./cmd/fuss

clean:
	rm -f fuss
