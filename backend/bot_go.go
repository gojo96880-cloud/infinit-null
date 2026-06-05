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
	"path/filepath"
	"strings"
	"time"
)

const gatewayURL = "http://localhost:8080/protected"
const botToken = "IL_TUO_JWT_TOKEN_QUI"
const quarantineDir = "/workspaces/infinit-null/quarantine" // Percorso della cartella di quarantena

var fileRegistry = map[string]string{
	"/workspaces/infinit-null/go.work": "", 
}

func main() {
	log.Println("⚡ Agente di Protezione Avanzato con Quarantena avviato...")
	
	// Crea la cartella di quarantena se non esiste sul dispositivo
	err := os.MkdirAll(quarantineDir, 0755)
	if err != nil {
		log.Fatalf("[❌] Impossibile creare la cartella di quarantena: %v", err)
	}

	initializeFileHashes()

	for {
		log.Println("[🔍] Scansione di sicurezza periodica in corso...")
		checkSuspiciousProcesses()
		checkFileIntegrity()
		time.Sleep(10 * time.Second)
	}
}

func initializeFileHashes() {
	for filePath := range fileRegistry {
		hash, err := calculateFileHash(filePath)
		if err == nil {
			fileRegistry[filePath] = hash
			log.Printf("[📋] Registrato stato iniziale per il file: %s (Hash: %s)\n", filePath, hash[:8])
		}
	}
}

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

func checkFileIntegrity() {
	for filePath, oldHash := range fileRegistry {
		currentHash, err := calculateFileHash(filePath)
		if err != nil {
			continue
		}

		if oldHash != "" && currentHash != oldHash {
			log.Printf("[🚨 INTEGRITÀ VIOLATA] Il file %s è stato modificato abusivamente!\n", filePath)
			
			// ATTIVAZIONE QUARANTENA: Isola immediatamente il file compromesso
			isolateFile(filePath)

			reportThreatToGateway("File Tampering & Isolate: " + filePath)
			fileRegistry[filePath] = currentHash
		}
	}
}

// Funzione di isolamento balistico del file infetto
func isolateFile(filePath string) {
	fileName := filepath.Base(filePath)
	destination := filepath.Join(quarantineDir, fileName+"_compromised_"+time.Now().Format("20060102_150405"))

	// Sposta il file nella directory di quarantena per bloccarne l'esecuzione
	err := os.Rename(filePath, destination)
	if err != nil {
		log.Printf("[❌] Spostamento in quarantena fallito per %s: %v. Tento la rimozione sicura...\n", fileName, err)
		_ = os.Remove(filePath) // Se non riesce a spostarlo, lo elimina per sicurezza
		return
	}

	log.Printf("[🔒 QUARANTENA] File pericoloso NEUTRALIZZATO e spostato in: %s\n", destination)
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
		"status": "Blocked & Isolated",
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
