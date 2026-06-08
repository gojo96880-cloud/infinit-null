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

func isSQLInjection(input string) bool {
	cleanInput := strings.ToLower(input)
	patterns := []string{
		"' or", "\" or", "or 1=1", "or '1'='1", "union select", 
		"insert into", "drop table", "alter table", "--", "select *",
	}
	for _, pattern := range patterns {
		if strings.Contains(cleanInput, pattern) {
			return true
		}
	}
	return false
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
	http.HandleFunc("/admin/dashboard", rateLimitMiddleware(adminDashboardHandler)) 
	http.HandleFunc("/admin/unban", rateLimitMiddleware(adminUnbanHandler)) 
	http.HandleFunc("/admin/report", rateLimitMiddleware(adminReportHandler)) 
	http.HandleFunc("/admin/report/html", rateLimitMiddleware(adminHTMLReportHandler)) // Nuova rotta per il report grafico HTML

	log.Println("🚀 API Gateway attivo con Generatore Report Grafici HTML...")
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

// GESTORE REPORT HTML GRAFICO (Generazione cruscotto visivo)
func adminHTMLReportHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Accesso negato", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	payload, err := ValidateToken(tokenStr)
	if err != nil || !strings.Contains(payload, `"role":"admin"`) {
		http.Error(w, "🚫 Privilegi Admin richiesti.", http.StatusForbidden)
		return
	}

	var totalThreats int
	_ = DB.QueryRow("SELECT COUNT(*) FROM threat_logs").Scan(&totalThreats)

	var bannedIPsCount int
	_ = DB.QueryRow("SELECT COUNT(*) FROM banned_ips").Scan(&bannedIPsCount)

	rows, err := DB.Query("SELECT id, event, status, timestamp FROM threat_logs ORDER BY id DESC LIMIT 100")
	if err != nil {
		http.Error(w, "Errore DB", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Costruzione dell'interfaccia visiva HTML + CSS incorporato
	var html strings.Builder
	html.WriteString(`<html><head><meta charset="utf-8"><title>Cybersecurity Audit Report</title>`)
	html.WriteString(`<style>body{font-family:Arial,sans-serif;background:#0f172a;color:#f8fafc;padding:40px;}`)
	html.WriteString(`.card-container{display:flex;gap:20px;margin-bottom:30px;}`)
	html.WriteString(`.card{background:#1e293b;padding:20px;border-radius:8px;flex:1;text-align:center;border:1px solid #334155;}`)
	html.WriteString(`.card h2{margin:0;font-size:36px;color:#38bdf8;}`)
	html.WriteString(`table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;}`)
	html.WriteString(`th,td{padding:12px;text-align:left;border-bottom:1px solid #334155;}`)
	html.WriteString(`th{background:#334155;color:#38bdf8;}`)
	html.WriteString(`.badge{padding:4px 8px;border-radius:4px;font-size:12px;font-weight:bold;background:#ef4444;color:#fff;}`)
	html.WriteString(`</style></head><body>`)
	html.WriteString(`<h1>🛡️ Infinit-Null Security Audit Dashboard</h1>`)
	html.WriteString(fmt.Sprintf("<p>📅 Report aggiornato live in data: %s</p>", time.Now().Format("2006-01-02 15:04:05")))
	
	html.WriteString(`<div class="card-container">`)
	html.WriteString(fmt.Sprintf(`<div class="card"><p>Minacce Evitate</p><h2>%d</h2></div>`, totalThreats))
	html.WriteString(fmt.Sprintf(`<div class="card"><p>IP Bloccati nel Firewall</p><h2>%d</h2></div>`, bannedIPsCount))
	html.WriteString(`</div>`)

	html.WriteString(`<h2>📋 Registro degli Ultimi Eventi Critici</h2>`)
	html.WriteString(`<table><tr><th>ID</th><th>Timestamp</th><th>Tipo Evento</th><th>Stato Sistema</th></tr>`)

	for rows.Next() {
		var entry ThreatLogEntry
		if err := rows.Scan(&entry.ID, &entry.Event, &entry.Status, &entry.Timestamp); err == nil {
			html.WriteString(fmt.Sprintf("<tr><td>%d</td><td>%s</td><td>%s</td><td><span class=\"badge\">%s</span></td></tr>", 
				entry.ID, entry.Timestamp, entry.Event, entry.Status))
		}
	}
	html.WriteString(`</table></body></html>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html.String()))
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
	if isSQLInjection(creds.Username) || isSQLInjection(creds.Password) {
		http.Error(w, "🛡️ Input non valido.", http.StatusBadRequest)
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
