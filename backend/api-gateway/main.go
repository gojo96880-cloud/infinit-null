package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ThreatReport struct {
	Event  string `json:"event"`
	Status string `json:"status"`
}

type ThreatLogEntry struct {
	ID        int    `json:"id"`
	Event     string `json:"event"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// STRUTTURA PER IL RATE LIMITER (Rilevamento DDoS / Brute-Force)
type IPRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
}

var Limiter = IPRateLimiter{
	requests: make(map[string][]time.Time),
}

// Middleware di controllo: Massimo 5 richieste in una finestra di 5 secondi
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		// Pulisce la porta dal formato dell'IP se presente
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		Limiter.mu.Lock()
		now := time.Now()
		
		// Rimuove i vecchi timestamp fuori dalla finestra dei 5 secondi
		var validRequests []time.Time
		for _, t := range Limiter.requests[ip] {
			if now.Sub(t) < 5*time.Second {
				validRequests = append(validRequests, t)
			}
		}

		// Verifica se ha superato il limite di 5 richieste
		if len(validRequests) >= 5 {
			Limiter.mu.Unlock()
			log.Printf("[🚨 ALLERTA DDoS] Rilevato traffico anomalo o Brute-Force dall'IP: %s. Richiesta bloccata.\n", ip)
			http.Error(w, "🛡️ Troppe richieste! Rilevato potenziale attacco. Riprova più tardi.", http.StatusTooManyRequests)
			return
		}

		// Aggiunge la richiesta attuale e aggiorna la mappa
		validRequests = append(validRequests, now)
		Limiter.requests[ip] = validRequests
		Limiter.mu.Unlock()

		next(w, r)
	}
}

func main() {
	InitDB()

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

	// Applichiamo il filtro protettivo (Middleware) a tutte le rotte pubbliche e sensibili
	http.HandleFunc("/register", rateLimitMiddleware(registerHandler))
	http.HandleFunc("/login", rateLimitMiddleware(loginHandler))
	http.HandleFunc("/protected", rateLimitMiddleware(protectedHandler))
	http.HandleFunc("/admin/dashboard", rateLimitMiddleware(adminDashboardHandler))

	log.Println("🚀 API Gateway in ascolto sulla porta :8080 con protezione DDoS attiva...")
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

	if r.Method == http.MethodPost {
		var report ThreatReport
		if err := json.NewDecoder(r.Body).Decode(&report); err == nil && report.Event != "" {
			log.Println("\n" + strings.Repeat("*", 60))
			log.Printf("[🚨 ALLERTA DI SICUREZZA CRITICA] RILEVATO ATTACCO SUL DISPOSITIVO!")
			log.Printf("[👉 EVENTO]: %s", report.Event)
			log.Printf("[🔒 STATO OPERATIVO]: %s", report.Status)
			log.Println(strings.Repeat("*", 60) + "\n")

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

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Accesso negato: Token mancante", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	_, err := ValidateToken(tokenStr)
	if err != nil {
		http.Error(w, "Accesso negato: Sessione non valida", http.StatusUnauthorized)
		return
	}

	rows, err := DB.Query("SELECT id, event, status, timestamp FROM threat_logs ORDER BY id DESC")
	if err != nil {
		http.Error(w, "Errore caricamento log della console", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []ThreatLogEntry
	for rows.Next() {
		var entry ThreatLogEntry
		if err := rows.Scan(&entry.ID, &entry.Event, &entry.Status, &entry.Timestamp); err == nil {
			logs = append(logs, entry)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}
