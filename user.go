package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type User struct {
	ID          int
	Email       string
	Password    string
	TotpEnabled bool
	TotpSecret  string
}

var users = []*User{
	{ID: 1, Email: "bob@example.com", Password: "test"},
}

// loginToken -> userID
var pendingLogins = map[string]int{}

// sessionID -> userID
var sessions = map[string]int{}

func login(email, password string) (string, error) {
	user, err := findUser(email)
	if err != nil {
		return "", err
	}

	if user.Password != password {
		return "", fmt.Errorf("invalid password")
	}
	// Passwort korrekt → Login-Token erzeugen
	token := randomString()

	// token speichern um später den User zuordnen zu können
	pendingLogins[token] = user.ID

	return token, nil
}

func findUser(email string) (*User, error) {
	for _, u := range users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func findUserByID(userID int) (*User, error) {
	for _, u := range users {
		if u.ID == userID {
			return u, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func randomString() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
