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

type IPRateLimiter struct {
	mu           sync.Mutex
	requests     map[string][]time.Time
	violationCount map[string]int // Traccia quante volte un IP ha violato il limite
}

var Limiter = IPRateLimiter{
	requests:       make(map[string][]time.Time),
	violationCount: make(map[string]int),
}

// Middleware di controllo avanzato con Firewall / Ban permanente
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		// 1. CONTROLLO FIREWALL: Verifica se l'IP è bannato permanentemente nel DB
		var isBanned int
		err := DB.QueryRow("SELECT COUNT(*) FROM banned_ips WHERE ip = ?", ip).Scan(&isBanned)
		if err == nil && isBanned > 0 {
			log.Printf("[🛡️ FIREWALL] Richiesta RESPINTA ALL'ISTANTE da IP bannato: %s\n", ip)
			http.Error(w, "💀 Accesso negato permanentemente. Il tuo IP è stato inserito nella blacklist del sistema.", http.StatusForbidden)
			return
		}

		Limiter.mu.Lock()
		now := time.Now()
		
		var validRequests []time.Time
		for _, t := range Limiter.requests[ip] {
			if now.Sub(t) < 5*time.Second {
				validRequests = append(validRequests, t)
			}
		}

		// 2. VERIFICA SOGLIA CRITICA
		if len(validRequests) >= 5 {
			Limiter.violationCount[ip]++
			violations := Limiter.violationCount[ip]
			Limiter.mu.Unlock()

			log.Printf("[🚨 ALLERTA DDoS] Violazione dal'IP: %s. (Violazioni consecutive: %d/3)\n", ip, violations)

			// SE SUPERA LE 3 VIOLAZIONI CONSECUTIVE -> BAN PERMANENTE IN DB
			if violations >= 3 {
				_, dbErr := DB.Exec("INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)", ip)
				if dbErr == nil {
					log.Printf("[💀 BAN PERMANENTE] IP %s inserito nel FIREWALL per attacco recidivo!\n", ip)
				}
			}

			http.Error(w, "🛡️ Troppe richieste! Rilevato potenziale attacco.", http.StatusTooManyRequests)
			return
		}

		validRequests = append(validRequests, now)
		Limiter.requests[ip] = validRequests
		Limiter.mu.Unlock()

		next(w, r)
	}
}

func main() {
	InitDB()

	// Crea la tabella dei log minacce
	_, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS threat_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event TEXT,
			status TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	// NUOVA TABELLA FIREWALL: Memorizza gli IP bannati permanentemente
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS banned_ips (
			ip TEXT PRIMARY KEY,
			banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal("Errore creazione tabella firewall:", err)
	}

	go startDatabaseTTLWorker()

	http.HandleFunc("/register", rateLimitMiddleware(registerHandler))
	http.HandleFunc("/login", rateLimitMiddleware(loginHandler))
	http.HandleFunc("/protected", rateLimitMiddleware(protectedHandler))
	http.HandleFunc("/admin/dashboard", rateLimitMiddleware(adminDashboardHandler))

	log.Println("🚀 API Gateway attivo con FIREWALL permanente e protezione DDoS...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func startDatabaseTTLWorker() {
	for {
		log.Println("[🧹 SMANEGGIAMENTO] Avvio del controllo di manutenzione del Database...")
		result, err := DB.Exec("DELETE FROM threat_logs WHERE timestamp < datetime('now', '-30 days')")
		if err == nil {
			rowsAffected, _ := result.RowsAffected()
			if rowsAffected > 0 {
				log.Printf("[🧹 PULIZIA COMPLETATA] Rimossi %d log obsoleti.\n", rowsAffected)
			}
		}
		time.Sleep(24 * time.Hour)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}
	var creds UserCredentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		return
	}
	_ = RegisterUser(creds.Username, creds.Password)
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
		return
	}
	success, err := LoginUser(creds.Username, creds.Password)
	if err != nil || !success {
		http.Error(w, "Credenziali errate", http.StatusUnauthorized)
		return
	}
	token, _ := GenerateToken(creds.Username)
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
			log.Printf("[🚨 ALLERTA DI SICUREZZA CRITICA] RILEVATO ATTACCO!")
			log.Printf("[👉 EVENTO]: %s", report.Event)
			log.Println(strings.Repeat("*", 60) + "\n")

			_, _ = DB.Exec("INSERT INTO threat_logs (event, status) VALUES (?, ?)", report.Event, report.Status)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"allerta_ricevuta"}`))
			return
		}
	}
	w.Write([]byte("🔓 Accesso consentito!"))
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Accesso negato", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	_, err := ValidateToken(tokenStr)
	if err != nil {
		http.Error(w, "Accesso negato", http.StatusUnauthorized)
		return
	}

	rows, err := DB.Query("SELECT id, event, status, timestamp FROM threat_logs ORDER BY id DESC")
	if err != nil {
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
