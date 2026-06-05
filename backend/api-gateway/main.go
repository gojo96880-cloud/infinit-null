package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
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

type UnbanRequest struct {
	IP string `json:"ip"`
}

// Struttura avanzata per la Dashboard con Statistiche Aggregate
type DashboardResponse struct {
	TotalThreatsBlocked int              `json:"total_threats_blocked"`
	ActiveBannedIPs     int              `json:"active_banned_ips"`
	RecentLogs          []ThreatLogEntry `json:"recent_logs"`
}

type IPRateLimiter struct {
	mu             sync.Mutex
	requests       map[string][]time.Time
	violationCount map[string]int
}

var Limiter = IPRateLimiter{
	requests:       make(map[string][]time.Time),
	violationCount: make(map[string]int),
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		var isBanned int
		err := DB.QueryRow("SELECT COUNT(*) FROM banned_ips WHERE ip = ?", ip).Scan(&isBanned)
		if err == nil && isBanned > 0 {
			http.Error(w, "💀 Accesso negato permanentemente.", http.StatusForbidden)
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

		if len(validRequests) >= 5 {
			Limiter.violationCount[ip]++
			violations := Limiter.violationCount[ip]
			Limiter.mu.Unlock()

			if violations >= 3 {
				_, _ = DB.Exec("INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)", ip)
			}
			http.Error(w, "🛡️ Troppe richieste!", http.StatusTooManyRequests)
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

	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS banned_ips (
			ip TEXT PRIMARY KEY,
			banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, _ = DB.Exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer';")
	_, _ = DB.Exec("CREATE INDEX IF NOT EXISTS idx_threat_logs_timestamp ON threat_logs(timestamp);")
	_, _ = DB.Exec("CREATE INDEX IF NOT EXISTS idx_threat_logs_id_desc ON threat_logs(id DESC);")

	go startDatabaseTTLWorker()

	http.HandleFunc("/register", rateLimitMiddleware(registerHandler))
	http.HandleFunc("/login", rateLimitMiddleware(loginHandler))
	http.HandleFunc("/protected", rateLimitMiddleware(protectedHandler))
	http.HandleFunc("/admin/dashboard", rateLimitMiddleware(adminDashboardHandler)) // Dashboard con contatore analitico
	http.HandleFunc("/admin/unban", rateLimitMiddleware(adminUnbanHandler)) 
	http.HandleFunc("/admin/report", rateLimitMiddleware(adminReportHandler)) 

	log.Println("🚀 API Gateway attivo con Contatore Statistico in tempo reale...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func startDatabaseTTLWorker() {
	for {
		_, _ = DB.Exec("DELETE FROM threat_logs WHERE timestamp < datetime('now', '-30 days')")
		time.Sleep(24 * time.Hour)
	}
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

	// 📊 CALCOLO DELLE METRICHE AGGREGATE
	var totalThreats int
	_ = DB.QueryRow("SELECT COUNT(*) FROM threat_logs").Scan(&totalThreats)

	var bannedIPsCount int
	_ = DB.QueryRow("SELECT COUNT(*) FROM banned_ips").Scan(&bannedIPsCount)

	// Estrazione dei log recenti
	rows, err := DB.Query("SELECT id, event, status, timestamp FROM threat_logs ORDER BY id DESC LIMIT 50")
	if err != nil {
		http.Error(w, "Errore caricamento log", http.StatusInternalServerError)
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

	// Costruisce la risposta unificata della Dashboard
	response := DashboardResponse{
		TotalThreatsBlocked: totalThreats,
		ActiveBannedIPs:     bannedIPsCount,
		RecentLogs:          logs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func adminReportHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Accesso negato", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	payload, err := ValidateToken(tokenStr)
	if err != nil || !strings.Contains(payload, `"role":"admin"`) {
		http.Error(w, "🚫 Privilegi di Amministratore richiesti.", http.StatusForbidden)
		return
	}

	rows, err := DB.Query("SELECT id, event, status, timestamp FROM threat_logs ORDER BY id DESC")
	if err != nil {
		http.Error(w, "Errore estrazione dati", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var reportBuilder strings.Builder
	reportBuilder.WriteString("============================================================\n")
	reportBuilder.WriteString("      REPORT DI AUDIT DI SICUREZZA - ENTERPRISE PLATFORM     \n")
	reportBuilder.WriteString(fmt.Sprintf("📅 Data Generazione: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	reportBuilder.WriteString("============================================================\n\n")

	count := 0
	for rows.Next() {
		var entry ThreatLogEntry
		if err := rows.Scan(&entry.ID, &entry.Event, &entry.Status, &entry.Timestamp); err == nil {
			count++
			reportBuilder.WriteString(fmt.Sprintf("[%d] ⏰ DATA: %s\n", count, entry.Timestamp))
			reportBuilder.WriteString(fmt.Sprintf("    ⚠️ INTERCETTAZIONE: %s\n", entry.Event))
			reportBuilder.WriteString(fmt.Sprintf("    🔒 STATO PROTEZIONE: %s\n", entry.Status))
			reportBuilder.WriteString("------------------------------------------------------------\n")
		}
	}

	reportBuilder.WriteString(fmt.Sprintf("\n📊 Riepilogo complessivo: Rilevate ed Evitate %d minacce negli ultimi 30 giorni.\n", count))
	reportBuilder.WriteString("🏁 Fine del Documento Ufficiale di Audit.\n")

	w.Header().Set("Content-Disposition", "attachment; filename=report_sicurezza.txt")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(reportBuilder.String()))
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
	if creds.Role == "" {
		creds.Role = "viewer"
	}
	_ = RegisterUser(creds.Username, creds.Password)
	_, _ = DB.Exec("UPDATE users SET role = ? WHERE username = ?", creds.Role, creds.Username)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message":"Utente registrato correttamente!"}`))
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
	var role string
	_ = DB.QueryRow("SELECT role FROM users WHERE username = ?", creds.Username).Scan(&role)
	token, _ := GenerateToken(creds.Username, role)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func adminUnbanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metodo non consentito", http.StatusMethodNotAllowed)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Accesso negato", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	payload, err := ValidateToken(tokenStr)
	if err != nil || !strings.Contains(payload, `"role":"admin"`) {
		http.Error(w, "🚫 Azione consentita solo agli amministratori.", http.StatusForbidden)
		return
	}
	var req UnbanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		return
	}
	_, _ = DB.Exec("DELETE FROM banned_ips WHERE ip = ?", req.IP)
	Limiter.mu.Lock()
	delete(Limiter.violationCount, req.IP)
	delete(Limiter.requests, req.IP)
	Limiter.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"IP sbannato dall'Amministratore!"}`))
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
