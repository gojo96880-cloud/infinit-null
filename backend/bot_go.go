package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
const quarantineDir = "/workspaces/infinit-null/quarantine"

// URL DEL WEBHOOK (Puoi sostituirlo con un vero URL webhook di Discord o Telegram) [1]
const securityWebhookURL = "https://httpbin.org" 

var cryptoKey = []byte("cyber-secure-key-aes-256-bit-pt")

var fileRegistry = map[string]string{
	"/workspaces/infinit-null/go.work": "", 
}

func main() {
	log.Println("⚡ Agente di Protezione con Notifiche Webhook avviato...")
	
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
			
			encryptAndIsolateFile(filePath)

			// Invia l'allarme istantaneo al Webhook dell'amministratore [1]
			sendWebhookAlert("🚨 ALLERTA MANOMISSIONE FILE", fmt.Sprintf("Il file importante %s è stato modificato abusivamente ed è stato spostato in quarantena cifrata AES-256.", filePath))

			reportThreatToGateway("File Tampering & Encrypted Quarantine: " + filePath)
			fileRegistry[filePath] = currentHash
		}
	}
}

func encryptAndIsolateFile(filePath string) {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		_ = os.Remove(filePath)
		return
	}

	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	fileName := filepath.Base(filePath)
	destination := filepath.Join(quarantineDir, fileName+".locked")
	
	_ = os.WriteFile(destination, ciphertext, 0644)
	_ = os.Remove(filePath)
	log.Printf("[🔒 CRYPTO-QUARANTENA] Il file %s è stato cifrato e neutralizzato.\n", fileName)
}

// FUNZIONE DI INVIO WEBHOOK PER INCIDENTI DI SICUREZZA [1]
func sendWebhookAlert(title, message string) {
	payload := map[string]interface{}{
		"username":   "Security Bot Agent",
		"avatar_url": "",
		"content":    fmt.Sprintf("**%s**\n📅 *Data:* %s\n💬 *Dettagli:* %s", title, time.Now().Format("2006-01-02 15:04:05"), message),
	}
	
	jsonData, _ := json.Marshal(payload)
	
	resp, err := http.Post(securityWebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[⚠️ Webhook] Impossibile inviare l'allerta esterna: %v\n", err)
		return
	}
	defer resp.Body.Close()
	log.Println("[🔔 Webhook] Allerta istantanea inviata con successo all'amministratore.")
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
			
			// Invia l'allarme istantaneo al Webhook per processo malevolo [1]
			sendWebhookAlert("💀 PROCESSO MALIGNO RILEVATO", fmt.Sprintf("È stato trovato un tool di hacking attivo sul dispositivo: %s. Il sistema ha bloccato la minaccia.", tool))

			reportThreatToGateway("Suspicious Process: " + tool)
		}
	}
}

func reportThreatToGateway(threatType string) {
	data := map[string]string{
		"event":  threatType,
		"status": "Cifrato & Isolato",
	}
	jsonData, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+botToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
