package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintln(w, "WIRECASE demo: simulated upstream failure")
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
