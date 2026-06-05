package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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

type IPRateLimiter struct {
	mu             sync.Mutex
	requests       map[string][]time.Time
	violationCount map[string]int
}

var Limiter = IPRateLimiter{
	requests:       make(map[string][]time.Time),
	violationCount: make(map[string]int),
}

// Chiave di cifratura simmetrica per i file di backup del DB (AES-256)
var backupCryptoKey = []byte("key-secure-database-backup-256b")

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

	// AVVIO DELLA ROUTINE DI MANUTENZIONE E BACKUP CIFRATO
	go startDatabaseManutentionWorker()

	http.HandleFunc("/register", rateLimitMiddleware(registerHandler))
	http.HandleFunc("/login", rateLimitMiddleware(loginHandler))
	http.HandleFunc("/protected", rateLimitMiddleware(protectedHandler))
	http.HandleFunc("/admin/dashboard", rateLimitMiddleware(adminDashboardHandler))
	http.HandleFunc("/admin/unban", rateLimitMiddleware(adminUnbanHandler)) 
	http.HandleFunc("/admin/report", rateLimitMiddleware(adminReportHandler)) 

	log.Println("🚀 API Gateway attivo con modulo di Backup Automatico Cifrato...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// Worker unico per la manutenzione e il backup sicuro dei dati
func startDatabaseManutentionWorker() {
	backupDir := "/workspaces/infinit-null/backups"
	_ = os.MkdirAll(backupDir, 0755)

	for {
		log.Println("[🧹 MANUTENZIONE] Avvio del ciclo periodico di pulizia log...")
		_, _ = DB.Exec("DELETE FROM threat_logs WHERE timestamp < datetime('now', '-30 days')")

		log.Println("[💾 BACKUP] Avvio della procedura di backup cifrato AES-256...")
		err := encryptAndBackupDatabase(backupDir)
		if err != nil {
			log.Println("[❌] Errore critico durante la creazione del backup del Database:", err)
		}

		// Attende 24 ore prima del prossimo ciclo completo
		time.Sleep(24 * time.Hour)
	}
}

// Legge il file SQLite attuale, lo cifra al volo e lo salva in un archivio marcato
func encryptAndBackupDatabase(backupDir string) error {
	dbBytes, err := os.ReadFile("./cybersecurity.db")
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(backupCryptoKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Cifratura asimmetrica sicura del file binario del DB
	encryptedData := gcm.Seal(nonce, nonce, dbBytes, nil)

	backupFileName := fmt.Sprintf("db_backup_%s.enc", time.Now().Format("20060102_150405"))
	backupPath := backupDir + "/" + backupFileName

	err = os.WriteFile(backupPath, encryptedData, 0600)
	if err != nil {
		return err
	}

	log.Printf("[🔒 BACKUP COMPLETATO] Il Database è stato isolato e blindato in: %s\n", backupFileName)
	return nil
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
