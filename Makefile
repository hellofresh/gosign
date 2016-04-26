export GOPATH=$(CURDIR)/.go

dep-update:
	go get -u "github.com/ianmcmahon/encoding_ssh"
	go get -u "github.com/bcampbell/fuzzytime"
	go get -u "gopkg.in/check.v1"

fmt:
	gofmt -s=true -w $(shell find . -type f -name '*.go' -not -path "./.go*")

test:
	go test -v ./...
