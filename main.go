package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (ac *apiConfig) metricsEndpoint(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write(fmt.Appendf(nil, "Hits: %d", ac.fileserverHits.Load()))
}

func (ac *apiConfig) resetEndpoint(w http.ResponseWriter, req *http.Request) {
	ac.fileserverHits.Store(0)
}

func (ac *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			ac.fileserverHits.Add(1)
			next.ServeHTTP(w, req)
		},
	)
}

func main() {
	apiCfg := apiConfig{}
	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	mux.HandleFunc("/healthz", readinessEndpoint)

	mux.HandleFunc("/metrics", apiCfg.metricsEndpoint)

	mux.HandleFunc("/reset", apiCfg.resetEndpoint)

	mux.Handle(
		"/app/",
		apiCfg.middlewareMetricsInc(
			http.StripPrefix(
				"/app",
				http.FileServer(http.Dir(".")),
			),
		),
	)

	server.ListenAndServe()
}

func readinessEndpoint(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}
