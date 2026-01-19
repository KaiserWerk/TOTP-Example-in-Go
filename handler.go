package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

var templates = template.Must(template.ParseGlob("templates/*.html"))

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	cookie, err := r.Cookie("session_id")
	if err == nil {
		sessionID := cookie.Value
		userID, ok := sessions[sessionID]
		if ok {
			user, err := findUserByID(userID)
			if err == nil {
				data["Email"] = user.Email
			}
		}

	}

	err = templates.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		fmt.Println("Error executing template:", err)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// remove leftover session cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
	})

	data := map[string]any{}
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "login.html", nil)
		if err != nil {
			fmt.Println("Error executing template:", err)
		}
		return
	}

	if r.Method == http.MethodPost {

		email := r.FormValue("email")
		password := r.FormValue("password")

		user, err := findUser(email)
		if err != nil || user.Password != password {
			data["Message"] = "Invalid credentials"
			err = templates.ExecuteTemplate(w, "login.html", data)
			if err != nil {
				fmt.Println("Error executing template:", err)
			}
			return
		}

		if user.TotpEnabled {
			loginToken, err := login(email, password)
			if err != nil {
				data["Message"] = "Login failed"
				err = templates.ExecuteTemplate(w, "login.html", data)
				if err != nil {
					fmt.Println("Error executing template:", err)
				}
				return
			}
			http.Redirect(w, r, "/login/2fa?token="+loginToken, http.StatusSeeOther)
			return

		} else {
			// set cookie with session ID if 2FA is not enabled
			sessionID := randomString()
			sessions[sessionID] = user.ID
			http.SetCookie(w, &http.Cookie{
				Name:  "session_id",
				Value: sessionID,
			})
			// redirect to 2fa setup page
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

	}
}

func login2FAHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	if r.Method == http.MethodGet {
		loginToken := r.URL.Query().Get("token")
		if loginToken == "" {
			http.Error(w, "Missing login token", http.StatusBadRequest)
			return
		}
		data["LoginToken"] = loginToken
		err := templates.ExecuteTemplate(w, "login_2fa.html", data)
		if err != nil {
			fmt.Println("Error executing template:", err)
		}
		return
	}
	if r.Method == http.MethodPost {
		loginToken := r.FormValue("login_token")
		code := r.FormValue("code")

		_, ok := pendingLogins[loginToken]
		if !ok {
			data["Message"] = "no pending login found"
			err := templates.ExecuteTemplate(w, "login_2fa.html", data)
			if err != nil {
				fmt.Println("Error executing template:", err)
			}
			return
		}

		// find the user by the login token
		userID := pendingLogins[loginToken]
		user, err := findUserByID(userID)
		if err != nil {
			data["Message"] = "user not found"
			err = templates.ExecuteTemplate(w, "login_2fa.html", data)
			if err != nil {
				fmt.Println("Error executing template:", err)
			}
			return
		}

		valid := totp.Validate(code, user.TotpSecret)
		delete(pendingLogins, loginToken) // Token nur einmal verwenden

		if !valid {
			data["Message"] = "invalid authentication code"
			err = templates.ExecuteTemplate(w, "login_2fa.html", data)
			if err != nil {
				fmt.Println("Error executing template:", err)
			}
			return
		}

		// 2FA erfolgreich → Session erstellen
		sessionID := randomString()
		sessions[sessionID] = user.ID
		delete(pendingLogins, loginToken)

		// set a cookie with a session ID
		http.SetCookie(w, &http.Cookie{
			Name:  "session_id",
			Value: sessionID,
		})
		data["Message"] = "Login successful"
		err = templates.ExecuteTemplate(w, "login.html", data)
		if err != nil {
			fmt.Println("Error executing template:", err)
		}
		return
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	if r.Method == http.MethodGet {
		err := templates.ExecuteTemplate(w, "register.html", data)
		if err != nil {
			fmt.Println("Error executing template:", err)
		}
		return
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		_, err := findUser(email)
		if err == nil {
			data["Message"] = "User already exists"
			err = templates.ExecuteTemplate(w, "register.html", data)
			if err != nil {
				fmt.Println("Error executing template:", err)
			}
			return
		}

		// add user
		newUser := &User{
			ID:       len(users) + 1,
			Email:    email,
			Password: password,
		}
		users = append(users, newUser)
		data["Message"] = "Registration successful"
		err = templates.ExecuteTemplate(w, "register.html", data)
		if err != nil {
			fmt.Println("Error executing template:", err)
		}
	}
}

func setup2FAHandler(w http.ResponseWriter, r *http.Request) {
	// get session ID from cookie
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Cookie not found or empty", http.StatusUnauthorized)
		return
	}

	sessionID := cookie.Value
	userID, ok := sessions[sessionID]
	if !ok {
		http.Error(w, "UserID not found", http.StatusUnauthorized)
		return
	}

	user, err := findUserByID(userID)
	if err != nil {
		http.Error(w, "User not found: "+err.Error(), http.StatusUnauthorized)
		return
	}

	data := map[string]any{}

	if r.Method == http.MethodGet {

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      issuer,
			AccountName: user.Email,
		})
		if err != nil {
			http.Error(w, "Error generating TOTP key: "+err.Error(), http.StatusInternalServerError)
			return
		}

		secret := key.Secret() // Base32
		user.TotpSecret = secret
		otpauthURL := key.URL()

		// generate QR code
		png, _ := qrcode.Encode(otpauthURL, qrcode.Medium, 256)

		data["QRCode"] = base64.StdEncoding.EncodeToString(png)

		err = templates.ExecuteTemplate(w, "setup_2fa.html", data)
		if err != nil {
			fmt.Println("Error executing template:", err)
		}
	}

	if r.Method == http.MethodPost {
		code := r.FormValue("code")
		valid := totp.Validate(code, user.TotpSecret)
		if !valid {
			data["Message"] = "Invalid authentication code"
			templates.ExecuteTemplate(w, "setup_2fa.html", data)
			return
		}
		user.TotpEnabled = true
		data["Message"] = "2FA setup successful"
		err = templates.ExecuteTemplate(w, "setup_2fa.html", data)
		if err != nil {
			fmt.Println("Error executing template:", err)
		}
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// get the session ID
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "No session found", http.StatusUnauthorized)
		return
	}

	sessionID := cookie.Value
	// delete the session
	delete(sessions, sessionID)

	// remove session cookie
	http.SetCookie(w, &http.Cookie{})

	// back to start
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func protectedPageHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Cookie not found or empty", http.StatusUnauthorized)
		return
	}

	sessionID := cookie.Value
	userID, ok := sessions[sessionID]
	if !ok {
		http.Error(w, "UserID not found", http.StatusUnauthorized)
		return
	}

	user, err := findUserByID(userID)
	if err != nil {
		http.Error(w, "User not found: "+err.Error(), http.StatusUnauthorized)
		return
	}

	data := map[string]any{}
	data["Email"] = user.Email
	err = templates.ExecuteTemplate(w, "protected.html", data)
	if err != nil {
		fmt.Println("Error executing template:", err)
	}
}
