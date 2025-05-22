package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/45uperman/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type ChirpyUser struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type apiConfig struct {
	fileserverHits atomic.Int32
	charLimit      atomic.Int32
	profaneWords   []string
	censorStr      string
	dbQueries      *database.Queries
	platform       string
	mu             sync.RWMutex
}

func (ac *apiConfig) createUserEndpoint(w http.ResponseWriter, req *http.Request) {
	type reqVals struct {
		Email string `json:"email"`
	}

	var rv reqVals
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&rv)
	if err != nil {
		fmt.Printf("Error decoding create user request: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if rv.Email == "" {
		respondWithError(w, 400, "user needs an email")
		return
	}

	dbUser, err := ac.dbQueries.CreateUser(
		context.Background(),
		database.CreateUserParams{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Email:     rv.Email,
		},
	)
	if err != nil {
		if err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"` {
			respondWithError(w, 400, "email already taken")
		}
		fmt.Printf("Error decoding making CreateUser query: %s\n", err)
		w.WriteHeader(500)
		return
	}

	respondWithJson(w, 201, ChirpyUser(dbUser))
}

func (ac *apiConfig) createChirpEndpoint(w http.ResponseWriter, req *http.Request) {
	type reqVals struct {
		Body   string    `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}

	var rv reqVals
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&rv)
	if err != nil {
		fmt.Printf("Error decoding chirp: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if len(rv.Body) > int(ac.charLimit.Load()) {
		respondWithError(w, 400, "chirp is too long")
		return
	}

	newChirp, err := ac.dbQueries.CreateChirp(
		context.Background(),
		database.CreateChirpParams{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Body: cleanChirpBody(
				ac.profaneWords,
				ac.censorStr,
				rv.Body,
			),
			UserID: rv.UserID,
		},
	)
	if err != nil {
		fmt.Printf("Error inserting chirp into database: %s\n", err)
		w.WriteHeader(500)
		return
	}

	respondWithJson(w, 201, Chirp(newChirp))
}

func (ac *apiConfig) getChirpEndpoint(w http.ResponseWriter, req *http.Request) {
	chirpIDString := req.PathValue("chirpID")
	if chirpIDString == "" {
		respondWithNotFound(w)
		return
	}

	var chirpID uuid.UUID
	chirpID.UnmarshalText([]byte(chirpIDString))

	dbChirp, err := ac.dbQueries.GetChirp(
		context.Background(),
		chirpID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithNotFound(w)
			return
		}
		fmt.Printf("Error getting chirp by ID: %s\n", err)
		w.WriteHeader(500)
		return
	}

	respondWithJson(w, 200, Chirp(dbChirp))
}

func (ac *apiConfig) getAllChirpsEndpoint(w http.ResponseWriter, req *http.Request) {
	dbChirps, err := ac.dbQueries.GetAllChirps(context.Background())
	if err != nil {
		fmt.Printf("Error getting chirps: %s\n", err)
		w.WriteHeader(500)
		return
	}

	var chirpyChirps []Chirp
	for _, dbChirp := range dbChirps {
		chirpyChirps = append(chirpyChirps, Chirp(dbChirp))
	}

	respondWithJson(w, 200, chirpyChirps)
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
	if ac.platform != "dev" {
		w.WriteHeader(403)
		w.Write([]byte("Forbidden"))
		return
	}

	ac.fileserverHits.Store(0)
	err := ac.dbQueries.DeleteAllUsers(context.Background())
	if err != nil {
		fmt.Printf("Error resetting: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(200)
	w.Write([]byte("OK"))
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
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
	}

	apiCfg := apiConfig{}
	apiCfg.charLimit.Store(140)
	apiCfg.profaneWords = []string{"kerfuffle", "sharbert", "fornax"}
	apiCfg.censorStr = "****"
	apiCfg.dbQueries = database.New(db)
	apiCfg.platform = os.Getenv("PLATFORM")

	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	mux.HandleFunc("GET /api/healthz", readinessEndpoint)

	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsEndpoint)

	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpEndpoint)

	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpEndpoint)

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsEndpoint)

	mux.HandleFunc("POST /admin/reset", apiCfg.resetEndpoint)

	mux.HandleFunc("POST /api/users", apiCfg.createUserEndpoint)

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

func respondWithNotFound(w http.ResponseWriter) {
	w.WriteHeader(404)
	w.Write([]byte("Not Found"))
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

func cleanChirpBody(profaneWords []string, censorStr, body string) string {
	currentWord := ""
	startIndex := -1
	endIndex := 0
	i := 0
	for i <= len(body) {
		if i == len(body) && startIndex >= 0 {
			cleanWord(
				profaneWords,
				censorStr,
				&body,
				startIndex,
				endIndex,
			)

			break
		}

		if unicode.IsSpace(rune(body[i])) && startIndex >= 0 {
			offset := cleanWord(
				profaneWords,
				censorStr,
				&body,
				startIndex,
				endIndex,
			)

			i -= offset
			currentWord = ""
			startIndex = -1
		} else {
			currentWord += string(body[i])
			if startIndex == -1 {
				startIndex = i
			}
			endIndex = i
		}
		i++
	}

	return body
}

func cleanWord(profaneWords []string, censorStr string, body *string, startIndex, endIndex int) (offset int) {
	derefBody := *body
	currentWord := derefBody[startIndex : endIndex+1]

	if slices.Contains(profaneWords, strings.ToLower(currentWord)) {
		leftCut := derefBody[:startIndex]
		rightCut := derefBody[endIndex+1:]

		*body = strings.Join([]string{leftCut, rightCut}, censorStr)

		offset = len(currentWord) - len(censorStr)
	}

	return
}
