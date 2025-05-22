package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPasswords(t *testing.T) {
	password_1 := "ilovegophers"
	password_2 := "pythonissstasssss"
	password_3 := "1337_60PH3R$ UN173! <^-^>"

	passwords := []string{password_1, password_2, password_3}

	for _, pswd := range passwords {
		pswdHash, err := HashPassword(pswd)
		if err != nil {
			fmt.Println(pswd, err)
			t.FailNow()
		}

		err = CheckPasswordHash(pswdHash, pswd)
		if err != nil {
			fmt.Println(pswd, err)
			t.FailNow()
		}
	}
}

func TestJWTs(t *testing.T) {
	id_1 := uuid.New()
	id_2 := uuid.New()
	id_3 := uuid.New()

	signing_key := "bootdotsigningkey"
	wrong_key := "honorsystemauthentication"

	ids := []uuid.UUID{id_1, id_2, id_3}

	for _, id := range ids {
		newJWT, err := MakeJWT(id, signing_key, 1*time.Second)
		if err != nil {
			fmt.Println(err)
			t.FailNow()
		}

		returnedID, err := ValidateJWT(newJWT, signing_key)
		if err != nil {
			fmt.Println(err)
			t.FailNow()
		}

		if returnedID != id {
			fmt.Printf("returned ID:\n'%s'\nnot equal to passed ID:\n'%s'\n", returnedID, id)
			t.FailNow()
		}

		_, err = ValidateJWT(newJWT, wrong_key)
		if err == nil {
			fmt.Println("failed to reject wrong key")
			t.FailNow()
		}

		time.Sleep(2 * time.Second)
		_, err = ValidateJWT(newJWT, signing_key)
		if err == nil {
			fmt.Println("failed to reject old JWT")
			t.FailNow()
		}
	}
}

func TestGetBearer(t *testing.T) {
	secretKey := "supersecretkey..."

	h1 := http.Header{}
	h1.Add("Authorization", "Bearer "+secretKey)

	h2 := http.Header{}
	h2.Add("Authorization", secretKey)

	h3 := http.Header{}
	h3.Add("Authorization", "")

	h4 := http.Header{}

	tokenString, err := GetBearerToken(h1)
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}

	if tokenString != secretKey {
		fmt.Println("GetBearer failed to get token string")
		t.FailNow()
	}

	_, err = GetBearerToken(h2)
	if err == nil {
		fmt.Println("GetBearer failed to throw error when given Authorization header with no 'Bearer ' prefix")
		t.FailNow()
	}

	_, err = GetBearerToken(h3)
	if err == nil {
		fmt.Println("GetBearer failed to throw error when given empty Authorization header")
		t.FailNow()
	}

	_, err = GetBearerToken(h4)
	if err == nil {
		fmt.Println("GetBearer failed to throw error when given no headers")
		t.FailNow()
	}
}
