package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

type Chirp struct {
	Body string `json:"body"`
}

func (c *Chirp) clean(profaneWords []string, censorStr string) {
	currentWord := ""
	startIndex := -1
	endIndex := 0
	i := 0
	for i <= len(c.Body) {
		if i == len(c.Body) && startIndex >= 0 {
			c.cleanWord(
				profaneWords,
				censorStr,
				startIndex,
				endIndex,
			)

			break
		}

		if unicode.IsSpace(rune(c.Body[i])) && startIndex >= 0 {
			offset := c.cleanWord(
				profaneWords,
				censorStr,
				startIndex,
				endIndex,
			)

			i -= offset
			currentWord = ""
			startIndex = -1
		} else {
			currentWord += string(c.Body[i])
			if startIndex == -1 {
				startIndex = i
			}
			endIndex = i
		}
		i++
	}
}

func (c *Chirp) cleanWord(profaneWords []string, censorStr string, startIndex, endIndex int) (offset int) {
	currentWord := c.Body[startIndex : endIndex+1]

	if slices.Contains(profaneWords, strings.ToLower(currentWord)) {
		leftCut := c.Body[:startIndex]
		rightCut := c.Body[endIndex+1:]

		c.Body = strings.Join([]string{leftCut, rightCut}, censorStr)

		offset = len(currentWord) - len(censorStr)
	}

	return
}

type apiConfig struct {
	fileserverHits atomic.Int32
	charLimit      atomic.Int32
	profaneWords   []string
	censorStr      string
	mu             sync.RWMutex
}

func (ac *apiConfig) validateChirpEndpoint(w http.ResponseWriter, req *http.Request) {
	var requestChirp *Chirp
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&requestChirp)
	if err != nil {
		fmt.Printf("Error decoding chirp: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if len(requestChirp.Body) > int(ac.charLimit.Load()) {
		respondWithError(w, 400, "Chirp is too long")
	} else {
		ac.mu.RLock()
		requestChirp.clean(ac.profaneWords, ac.censorStr)
		ac.mu.RUnlock()

		type returnVals struct {
			CleanedBody string `json:"cleaned_body"`
		}

		respBody := returnVals{
			CleanedBody: requestChirp.Body,
		}

		respondWithJson(w, 200, respBody)
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
	apiCfg.profaneWords = []string{"kerfuffle", "sharbert", "fornax"}
	apiCfg.censorStr = "****"

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

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	w.Write(fmt.Appendf(nil, `{"error":"%s"}`, msg))
}

func respondWithJson(w http.ResponseWriter, code int, payload any) error {
	w.WriteHeader(code)

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	w.Write(data)

	return nil
}
