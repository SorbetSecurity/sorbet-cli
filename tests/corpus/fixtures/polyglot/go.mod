module example.com/polyglot

go 1.22

require (
	github.com/gorilla/mux v1.8.1
	golang.org/x/text v0.14.0 // indirect
)

replace github.com/gorilla/mux => github.com/acme/mux v1.8.2
