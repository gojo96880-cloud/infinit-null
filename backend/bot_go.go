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

// STRINGHE OFFUSCATE IN ESADECIMALE (Nasconde URL, Token e percorsi ai software di Reverse Engineering)
const hexGatewayURL = "687474703a2f2f6c6f63616c686f73743a383038302f70726f746563746564" // http://localhost:8080/protected
const hexBotToken = "494c5f54554f5f4a57545f544f4b454e5f515549"                       // IL_TUO_JWT_TOKEN_QUI
const hexQuarantineDir = "2f776f726b7370616365732f696e66696e69742d6e756c6c2f71756172616e74696e65" // /workspaces/infinit-null/quarantine
const hexWebhookURL = "68747470733a2f2f6874747062696e2e6f72672f706f7374"               // https://httpbin.org

var cryptoKey = []byte("cyber-secure-key-aes-256-bit-pt")

var fileRegistry = map[string]string{
	"/workspaces/infinit-null/go.work": "", 
}

// Funzione di decodifica al volo (Risolve l'offuscamento in memoria solo quando necessario)
func decodeString(hexStr string) string {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func main() {
	log.Println("⚡ Agente di Protezione Corazzato e Offuscato avviato...")
	
	err := os.MkdirAll(decodeString(hexQuarantineDir), 0755)
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

			sendWebhookAlert("🚨 ALLERTA MANOMISSIONE FILE", fmt.Sprintf("Il file importante %s è stato modificato ed è stato spostato in quarantena cifrata AES-256.", filePath))

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
	destination := filepath.Join(decodeString(hexQuarantineDir), fileName+".locked")
	
	_ = os.WriteFile(destination, ciphertext, 0644)
	_ = os.Remove(filePath)
	log.Printf("[🔒 CRYPTO-QUARANTENA] Il file %s è stato cifrato e neutralizzato.\n", fileName)
}

func sendWebhookAlert(title, message string) {
	payload := map[string]interface{}{
		"username": "Security Bot Agent",
		"content":  fmt.Sprintf("**%s**\n📅 *Data:* %s\n💬 *Dettagli:* %s", title, time.Now().Format("2006-01-02 15:04:05"), message),
	}
	
	jsonData, _ := json.Marshal(payload)
	
	resp, err := http.Post(decodeString(hexWebhookURL), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
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
			
			sendWebhookAlert("💀 PROCESSO MALIGNO RILEVATO", fmt.Sprintf("È stato trovato un tool di hacking attivo sul dispositivo: %s.", tool))

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

	req, _ := http.NewRequest("POST", decodeString(hexGatewayURL), bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+decodeString(hexBotToken))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}
