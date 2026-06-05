package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Nuova struttura per ricevere i dati della minaccia inviati dal Bot
type ThreatReport struct {
	Event  string `json:"event"`
	Status string `json:"status"`
}

func main() {
	InitDB()

	// Creiamo la tabella per memorizzare lo storico dei log se non esiste (Opzione A)
	_, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS threat_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event TEXT,
			status TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal("Errore creazione tabella log minacce:", err)
	}

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/protected", protectedHandler)

	log.Println("🚀 API Gateway in ascolto sulla porta :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

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
		http.Error(w, "Errore registrazione", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message":"Utente registrato!"}`))
}

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
	token, err := GenerateToken(creds.Username)
	if err != nil {
		http.Error(w, "Errore token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Endpoint modificato per gestire l'allarme visivo e il database log
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Token mancante", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	_, err := ValidateToken(tokenStr)
	if err != nil {
		http.Error(w, "Token non valido", http.StatusUnauthorized)
		return
	}

	// Se la richiesta contiene un JSON con una minaccia, la gestiamo
	if r.Method == http.MethodPost {
		var report ThreatReport
		if err := json.NewDecoder(r.Body).Decode(&report); err == nil && report.Event != "" {
			
			// 1. ALLARME GIGANTE A SCHERMO (Opzione B)
			log.Println("\n" + strings.Repeat("*", 60))
			log.Printf("[🚨 ALLERTA DI SICUREZZA CRITICA] RILEVATO ATTACCO SUL DISPOSITIVO!")
			log.Printf("[👉 EVENTO]: %s", report.Event)
			log.Printf("[🔒 STATO OPERATIVO]: %s", report.Status)
			log.Println(strings.Repeat("*", 60) + "\n")

			// 2. SALVATAGGIO PERMANENTE NEL DATABASE (Opzione A)
			_, dbErr := DB.Exec("INSERT INTO threat_logs (event, status) VALUES (?, ?)", report.Event, report.Status)
			if dbErr != nil {
				log.Println("[❌] Errore durante il salvataggio del log nel Database:", dbErr)
			} else {
				log.Println("[💾] Minaccia registrata correttamente nello storico del Database.")
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"allerta_ricevuta"}`))
			return
		}
	}

	w.Write([]byte("🔓 Accesso consentito! Il canale di comunicazione con il gateway è sicuro."))
}
