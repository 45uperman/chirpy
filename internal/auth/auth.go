package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		&jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
			Subject:   userID.String(),
		},
	)
	newJWT, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	return newJWT, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		},
	)
	if err != nil {
		return uuid.UUID{}, err
	}

	idString, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}

	id, err := uuid.Parse(idString)
	if err != nil {
		return uuid.UUID{}, err
	}

	return id, nil
}

func GetAuthHeader(headers http.Header, prefix string) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("no authorization header")
	}

	headerVal := strings.TrimPrefix(authHeader, prefix+" ")
	if headerVal == authHeader || headerVal == "" {
		return "", fmt.Errorf("malformed authorization header '%s'", authHeader)
	}

	return headerVal, nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	token := hex.EncodeToString(key)

	return token, nil
}
