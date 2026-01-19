package main

import (
	"fmt"
	"net/http"
)

const (
	issuer  = "Local Test App"
	account = "alice@example.com"
)

func main() {
	http.HandleFunc("/", dashboardHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/login/2fa", login2FAHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/setup_2fa", setup2FAHandler)
	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("server listening on port 8000...")
	http.ListenAndServe(":8000", nil)
}
