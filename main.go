package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func main() {

	// Open a database connection
	db, err := sql.Open("sqlite3", "./bernice.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	schema,err := os.ReadFile("schema.sql") 
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(string(schema))
	if err != nil {
		log.Fatal(err)
	}
	var templates = template.Must(template.ParseGlob("templates/*.html")) 
	
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		registerPage(w, r, db, templates)
	} )
 
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		loginPage(w, r, db, templates)
	} ) 
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/welcome", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	
		userID, err := strconv.Atoi(cookie.Value)
		if err != nil {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
	
		var username string
		err = db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}
	
		err = templates.ExecuteTemplate(w, "welcome.html", struct {
			Username string
		}{Username: username})
		if err != nil {
			http.Error(w, "Unable to load template", http.StatusInternalServerError)
		}
	})
	
	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
} 

func registerUser(db *sql.DB, username, password string) error {
    // Hash the password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    log.Printf("Registering user: username=%s, hashedPassword=%s", username, hashedPassword)

    // Insert the new user into the database
    _, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
    if err != nil {
        return err
    }

    return nil
}

func registerPage(w http.ResponseWriter, r *http.Request,db *sql.DB, templates *template.Template) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		err := registerUser(db, username, password)
		if err != nil {
			http.Error(w, "Unable to register user", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	err := templates.ExecuteTemplate(w, "register.html", nil)
	if err != nil {
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
	}
}
func loginUser(db *sql.DB, username, password string) (int, error) {
    var hashedPassword string
    var userID int

    // Query the database for the user's ID and hashed password
    err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&userID, &hashedPassword)
    if err != nil {
        if err == sql.ErrNoRows {
            return 0, nil // User not found
        }
        return 0, err // Other database error
    }

    log.Printf("Login attempt: username=%s, userID=%d, hashedPassword=%s, enteredPassword=%s", username, userID, hashedPassword, password)

    // Compare the provided password with the hashed password
    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    if err != nil {
        log.Printf("Password comparison failed: %v", err)
        return 0, nil // Password does not match
    }

    return userID, nil // Login successful
}
 
func loginPage(w http.ResponseWriter, r *http.Request, db *sql.DB, templates *template.Template) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		userID, err := loginUser(db, username, password)
		if err != nil {
			http.Error(w, "Unable to login", http.StatusInternalServerError)
			return
		}

		if userID != 0  {
			http.SetCookie(w, &http.Cookie{
				Name:  "session_id",
				Value: strconv.Itoa(userID),
				Path: "/",
			})
			http.Redirect(w, r, "/welcome", http.StatusSeeOther)
			return
		} else {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			
			return
		}
	}

	err := templates.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
	}
}


func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
		Path: "/",
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

