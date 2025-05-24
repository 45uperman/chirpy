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

	"github.com/45uperman/chirpy/internal/auth"
	"github.com/45uperman/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type ChirpyUser struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	hashedPassword string
	IsChirpyRed    bool `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type RefreshToken struct {
	Token     string       `json:"token"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	UserID    uuid.UUID    `json:"user_id"`
	ExpiresAt time.Time    `json:"expires_at"`
	RevokedAt sql.NullTime `json:"revoked_at"`
}

type apiConfig struct {
	fileserverHits atomic.Int32
	charLimit      atomic.Int32
	profaneWords   []string
	censorStr      string
	dbQueries      *database.Queries
	platform       string
	secretKey      string
	polkaKey       string
	jwtExpiration  time.Duration
	rtExpiration   time.Duration
	mu             sync.RWMutex
}

func (ac *apiConfig) createUserEndpoint(w http.ResponseWriter, req *http.Request) {
	type reqVals struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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

	if rv.Password == "" {
		respondWithError(w, 400, "user needs a password")
		return
	}

	hashedPassword, err := auth.HashPassword(rv.Password)
	if err != nil {
		fmt.Printf("Error hashing user password: %s\n", err)
		w.WriteHeader(500)
		return
	}

	dbUser, err := ac.dbQueries.CreateUser(
		context.Background(),
		database.CreateUserParams{
			ID:             uuid.New(),
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
			Email:          rv.Email,
			HashedPassword: hashedPassword,
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

	respondWithJson(
		w,
		201,
		ChirpyUser{
			ID:          dbUser.ID,
			CreatedAt:   dbUser.CreatedAt,
			UpdatedAt:   dbUser.UpdatedAt,
			Email:       dbUser.Email,
			IsChirpyRed: dbUser.IsChirpyRed,
		},
	)
}

func (ac *apiConfig) updateUserEndpoint(w http.ResponseWriter, req *http.Request) {
	type reqVals struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var rv reqVals
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&rv)
	if err != nil {
		fmt.Printf("Error decoding create user request: %s\n", err)
		w.WriteHeader(500)
		return
	}

	tokenString, err := auth.GetAuthHeader(req.Header, "Bearer")
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	userID, err := auth.ValidateJWT(tokenString, ac.secretKey)
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	dbUser, err := ac.dbQueries.GetUser(context.Background(), userID)
	if err != nil {
		fmt.Printf("Error getting user for user update: %s\n", err)
		w.WriteHeader(500)
		return
	}

	email := dbUser.Email
	pswd := dbUser.HashedPassword

	if rv.Password != "" {
		pswd, err = auth.HashPassword(rv.Password)
		if err != nil {
			fmt.Printf("Error hashing password for user update: %s\n", err)
			w.WriteHeader(500)
			return
		}
	}
	if rv.Email != "" {
		email = rv.Email
	}

	updatedUser, err := ac.dbQueries.UpdateEmailAndPassword(
		context.Background(),
		database.UpdateEmailAndPasswordParams{
			ID:             userID,
			Email:          email,
			HashedPassword: pswd,
		},
	)
	if err != nil {
		fmt.Printf("Error updating user: %s\n", email)
		w.WriteHeader(500)
		return
	}

	respondWithJson(
		w,
		200,
		ChirpyUser{
			ID:          updatedUser.ID,
			CreatedAt:   dbUser.CreatedAt,
			UpdatedAt:   dbUser.UpdatedAt,
			Email:       updatedUser.Email,
			IsChirpyRed: dbUser.IsChirpyRed,
		},
	)
}

func (ac *apiConfig) giveUserChirpyRedEndpoint(w http.ResponseWriter, req *http.Request) {
	key, err := auth.GetAuthHeader(req.Header, "ApiKey")
	if err != nil || key != ac.polkaKey {
		respondWithUnauthorized(w)
		return
	}

	type reqVals struct {
		Event string `json:"event"`
		Data  struct {
			UserId string `json:"user_id"`
		} `json:"data"`
	}

	var rv reqVals
	decoder := json.NewDecoder(req.Body)
	err = decoder.Decode(&rv)
	if err != nil {
		fmt.Printf("Error decoding polka request for giveUserChirpyRed: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if rv.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}

	userID, err := uuid.Parse(rv.Data.UserId)
	if err != nil {
		respondWithError(w, 400, "malformed or missing user_id")
	}

	err = ac.dbQueries.GiveUserChirpyRed(context.Background(), userID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithNotFound(w)
			return
		}

		fmt.Printf("Error giving user chirpy red: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}

func (ac *apiConfig) loginEndpoint(w http.ResponseWriter, req *http.Request) {
	type reqVals struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var rv reqVals
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&rv)
	if err != nil {
		fmt.Printf("Error decoding login info: %s\n", err)
		w.WriteHeader(500)
		return
	}

	dbUser, err := ac.dbQueries.GetUserByEmail(context.Background(), rv.Email)
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	err = auth.CheckPasswordHash(dbUser.HashedPassword, rv.Password)
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	jwToken, err := auth.MakeJWT(dbUser.ID, ac.secretKey, ac.jwtExpiration)
	if err != nil {
		fmt.Printf("Error making JWT for login: %s\n", err)
		w.WriteHeader(500)
		return
	}

	rToken, err := auth.MakeRefreshToken()
	if err != nil {
		fmt.Printf("Error making refresh token for login: %s\n", err)
		w.WriteHeader(500)
		return
	}

	_, err = ac.dbQueries.CreateRefreshToken(
		context.Background(),
		database.CreateRefreshTokenParams{
			Token:     rToken,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			UserID:    dbUser.ID,
			ExpiresAt: time.Now().Add(ac.rtExpiration),
		},
	)
	if err != nil {
		fmt.Printf("Error inserting refresh token into database for login: %s\n", err)
		w.WriteHeader(500)
		return
	}

	type resVals struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
		JWToken     string    `json:"token"`
		RToken      string    `json:"refresh_token"`
	}

	respondWithJson(
		w,
		200,
		resVals{
			ID:          dbUser.ID,
			CreatedAt:   dbUser.CreatedAt,
			UpdatedAt:   dbUser.UpdatedAt,
			Email:       dbUser.Email,
			IsChirpyRed: dbUser.IsChirpyRed,
			JWToken:     jwToken,
			RToken:      rToken,
		},
	)
}

func (ac *apiConfig) refreshEndpoint(w http.ResponseWriter, req *http.Request) {
	tokenString, err := auth.GetAuthHeader(req.Header, "Bearer")
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	rToken, err := ac.dbQueries.GetRefreshToken(context.Background(), tokenString)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithUnauthorized(w)
			return
		}

		fmt.Printf("Error getting refresh token for refresh: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if rToken.ExpiresAt.Before(time.Now()) || rToken.RevokedAt.Valid {
		respondWithUnauthorized(w)
		return
	}

	jwToken, err := auth.MakeJWT(rToken.UserID, ac.secretKey, ac.jwtExpiration)
	if err != nil {
		fmt.Printf("Error making JWT for refresh: %s\n", err)
		w.WriteHeader(500)
		return
	}

	type resVals struct {
		Token string `json:"token"`
	}

	respondWithJson(w, 200, resVals{Token: jwToken})
}

func (ac *apiConfig) revokeEndpoint(w http.ResponseWriter, req *http.Request) {
	tokenString, err := auth.GetAuthHeader(req.Header, "Bearer")
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	err = ac.dbQueries.RevokeRefreshToken(
		context.Background(),
		database.RevokeRefreshTokenParams{
			Token:     tokenString,
			UpdatedAt: time.Now(),
		},
	)
	if err != nil {
		fmt.Printf("Error revoking refresh token: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}

func (ac *apiConfig) createChirpEndpoint(w http.ResponseWriter, req *http.Request) {
	type reqVals struct {
		Body string `json:"body"`
	}

	var rv reqVals
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&rv)
	if err != nil {
		fmt.Printf("Error decoding chirp: %s\n", err)
		w.WriteHeader(500)
		return
	}

	tokenString, err := auth.GetAuthHeader(req.Header, "Bearer")
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	tokenID, err := auth.ValidateJWT(tokenString, ac.secretKey)
	if err != nil {
		respondWithUnauthorized(w)
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
			UserID: tokenID,
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
	err := chirpID.UnmarshalText([]byte(chirpIDString))
	if err != nil {
		respondWithError(w, 400, "malformed chirpID")
		return
	}

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
	var authorID uuid.UUID
	var dbChirps []database.Chirp
	var err error

	sortOrder := req.URL.Query().Get("sort")

	authorIDStr := req.URL.Query().Get("author_id")
	if authorIDStr != "" {
		authorID, err = uuid.Parse(authorIDStr)
		if err != nil {
			respondWithError(w, 400, "malformed authorID")
			return
		}

		dbChirps, err = ac.dbQueries.GetChirpsByAuthor(
			context.Background(),
			authorID,
		)
	} else {
		dbChirps, err = ac.dbQueries.GetAllChirps(context.Background())
	}
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithNotFound(w)
			return
		}
		fmt.Printf("Error getting chirps: %s\n", err)
		w.WriteHeader(500)
		return
	}

	var chirpyChirps []Chirp
	for _, dbChirp := range dbChirps {
		chirpyChirps = append(chirpyChirps, Chirp(dbChirp))
	}

	if sortOrder == "desc" {
		slices.Reverse(chirpyChirps)
	}

	respondWithJson(w, 200, chirpyChirps)
}

func (ac *apiConfig) deleteChirpEndpoint(w http.ResponseWriter, req *http.Request) {
	tokenString, err := auth.GetAuthHeader(req.Header, "Bearer")
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	tokenID, err := auth.ValidateJWT(tokenString, ac.secretKey)
	if err != nil {
		respondWithUnauthorized(w)
		return
	}

	chirpIDString := req.PathValue("chirpID")
	if chirpIDString == "" {
		respondWithNotFound(w)
		return
	}

	var chirpID uuid.UUID
	err = chirpID.UnmarshalText([]byte(chirpIDString))
	if err != nil {
		respondWithError(w, 400, "malformed chirpID")
		return
	}

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

	if dbChirp.UserID != tokenID {
		w.WriteHeader(403)
		return
	}

	err = ac.dbQueries.DeleteChirp(context.Background(), chirpID)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithNotFound(w)
			return
		}
		fmt.Printf("Error deleting chirp by ID: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
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
	apiCfg.secretKey = os.Getenv("SECRET")
	apiCfg.polkaKey = os.Getenv("POLKA_KEY")
	apiCfg.jwtExpiration = time.Hour
	apiCfg.rtExpiration = time.Hour * 24 * 60

	mux := http.NewServeMux()
	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	mux.HandleFunc("GET /api/healthz", readinessEndpoint)

	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpEndpoint)

	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirpsEndpoint)

	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpEndpoint)

	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpEndpoint)

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsEndpoint)

	mux.HandleFunc("POST /admin/reset", apiCfg.resetEndpoint)

	mux.HandleFunc("POST /api/users", apiCfg.createUserEndpoint)

	mux.HandleFunc("PUT /api/users", apiCfg.updateUserEndpoint)

	mux.HandleFunc("POST /api/login", apiCfg.loginEndpoint)

	mux.HandleFunc("POST /api/refresh", apiCfg.refreshEndpoint)

	mux.HandleFunc("POST /api/revoke", apiCfg.revokeEndpoint)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.giveUserChirpyRedEndpoint)

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

func respondWithUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(401)
	w.Write([]byte("Unauthorized"))
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
