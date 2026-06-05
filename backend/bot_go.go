package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const gatewayURL = "http://localhost:8080/protected"
const botToken = "IL_TUO_JWT_TOKEN_QUI"

// Mappa per memorizzare gli hash dei file importanti e verificare se cambiano
var fileRegistry = map[string]string{
	"/workspaces/infinit-null/go.work": "", // Monitora il workspace di Go
}

func main() {
	log.Println("Encoding ⚡ Agente di Protezione Avanzato Client avviato...")
	
	// Inizializza gli hash dei file al primo avvio
	initializeFileHashes()

	for {
		log.Println("[🔍] Scansione di sicurezza periodica in corso...")
		checkSuspiciousProcesses()
		checkFileIntegrity()
		time.Sleep(10 * time.Second)
	}
}

// Calcola l'hash iniziale dei file per fare il confronto in seguito
func initializeFileHashes() {
	for filePath := range fileRegistry {
		hash, err := calculateFileHash(filePath)
		if err == nil {
			fileRegistry[filePath] = hash
			log.Printf("[📋] Registrato stato iniziale per il file: %s (Hash: %s)\n", filePath, hash[:8])
		}
	}
}

// Calcola l'hash SHA-256 di un file
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Controlla se i file registrati sono stati modificati abusivamente
func checkFileIntegrity() {
	for filePath, oldHash := range fileRegistry {
		currentHash, err := calculateFileHash(filePath)
		if err != nil {
			log.Printf("[⚠️ WARNING] Impossibile accedere al file tracciato: %s\n", filePath)
			continue
		}

		if oldHash != "" && currentHash != oldHash {
			log.Printf("[🚨 INTEGRITÀ VIOLATA] Il file %s è stato modificato abusivamente!\n", filePath)
			reportThreatToGateway("File Tampering: " + filePath)
			// Aggiorna l'hash per evitare allarmi infiniti sullo stesso evento
			fileRegistry[filePath] = currentHash
		}
	}
}

func checkSuspiciousProcesses() {
	cmd := exec.Command("ps", "aux")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return
	}

	outputStr := out.String()
	maliciousTools := []string{"nmap", "wireshark", "hydra", "metasploit", "nc"}

	for _, tool := range maliciousTools {
		if strings.Contains(strings.ToLower(outputStr), tool) {
			log.Printf("[🚨 MINACCIA RILEVATA] Trovato processo sospetto attivo: %s!\n", tool)
			reportThreatToGateway("Suspicious Process: " + tool)
		}
	}
}

func reportThreatToGateway(threatType string) {
	data := map[string]string{
		"event":  threatType,
		"status": "Blocked",
	}
	jsonData, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+botToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[⚠️] API Gateway offline. Allerta archiviata localmente per: %s\n", threatType)
		return
	}
	defer resp.Body.Close()
	log.Printf("[✅] Allerta inviata. Risposta server: %s\n", resp.Status)
}
