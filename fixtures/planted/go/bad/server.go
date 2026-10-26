package main

import (
	"log"
	"net/http"
	"time"
)

// serveUploads bounds only the header read, so a client can still send the
// body, or read the response, one byte at a time.
func serveUploads(h http.Handler) error {
	srv := &http.Server{ // expect: arbiter/go.http-server-no-timeout
		Addr:              ":8080",
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func serveDefault(h http.Handler) {
	log.Fatal(http.ListenAndServe(":9090", h)) // expect: arbiter/go.http-server-no-timeout
}
