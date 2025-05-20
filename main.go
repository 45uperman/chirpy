package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
)

type Chirp struct {
	Body string `json:"body"`
}

type apiConfig struct {
	fileserverHits atomic.Int32
	charLimit      atomic.Int32
}

func (ac *apiConfig) validateChirpEndpoint(w http.ResponseWriter, req *http.Request) {
	var requestChirp Chirp
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&requestChirp)
	if err != nil {
		fmt.Printf("Error decoding chirp: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if len(requestChirp.Body) > int(ac.charLimit.Load()) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"Chirp is too long"}`))
	} else {
		w.WriteHeader(200)
		w.Write([]byte(`{"valid":true}`))
	}
}

func (ac *apiConfig) metricsEndpoint(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)

	resBodyFormat :=
		`
		<html>
			<body>
				<h1>Welcome, Chirpy Admin</h1>
				<p>Chirpy has been visited %d times!</p>
			</body>
		</html>
	`
	w.Write(fmt.Appendf(nil, resBodyFormat, ac.fileserverHits.Load()))
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
	apiCfg.charLimit.Store(140)

	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	mux.HandleFunc("GET /api/healthz", readinessEndpoint)

	mux.HandleFunc("POST /api/validate_chirp", apiCfg.validateChirpEndpoint)

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsEndpoint)

	mux.HandleFunc("POST /admin/reset", apiCfg.resetEndpoint)

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
