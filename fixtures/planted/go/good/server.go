package main

import (
	"log"
	"net/http"
	"time"
)

func serveUploads(h http.Handler) error {
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServe()
}

func serveBounded(h http.Handler) {
	srv := &http.Server{Addr: ":9090", Handler: http.TimeoutHandler(h, 5*time.Second, "timeout")}
	srv.ReadTimeout = 10 * time.Second
	log.Fatal(srv.ListenAndServe())
}
