package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// Struttura per leggere i dati inviati dall'utente
type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	// 1. Inizializza il database all'avvio
	InitDB()

	// 2. Configurazione delle Rotte (Routing)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/protected", protectedHandler)

	// 3. Avvia il server sulla porta 8080
	log.Println("🚀 API Gateway in ascolto sulla porta :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// Gestore per la Registrazione
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}

	var creds UserCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Dati non validi", http.StatusBadRequest)
		return
	}

	if err := RegisterUser(creds.Username, creds.Password); err != nil {
		http.Error(w, "Errore durante la registrazione (utente potrebbe già esistere)", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message":"Utente registrato con successo!"}`))
}

// Gestore per il Login (Rilascia il JWT)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}

	var creds UserCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Dati non validi", http.StatusBadRequest)
		return
	}

	success, err := LoginUser(creds.Username, creds.Password)
	if err != nil || !success {
		http.Error(w, "Credenziali errate", http.StatusUnauthorized)
		return
	}

	// Genera il Token JWT reale salvato in jwt.go
	token, err := GenerateToken(creds.Username)
	if err != nil {
		http.Error(w, "Errore generazione token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Gestore Protetto (Accessibile solo con Token valido)
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Token mancante", http.StatusUnauthorized)
		return
	}

	// Estrae il token dal formato "Bearer <token>"
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	
	// Valida il token usando la logica di jwt.go
	payload, err := ValidateToken(tokenStr)
	if err != nil {
		http.Error(w, "Token non valido o scaduto", http.StatusUnauthorized)
		return
	}

	w.Write([]byte("🔓 Accesso consentito! Dati protetti letti con successo. Informazioni: " + payload))
}
