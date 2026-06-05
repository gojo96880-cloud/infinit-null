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

const hexGatewayURL = "687474703a2f2f6c6f63616c686f73743a383038302f70726f746563746564" 
const hexBotToken = "494c5f54554f5f4a57545f544f4b454e5f515549"                       
const hexQuarantineDir = "2f776f726b7370616365732f696e66696e69742d6e756c6c2f71756172616e74696e65" 
const hexWebhookURL = "68747470733a2f2f6874747062696e2e6f72672f706f7374"               

var cryptoKey = []byte("cyber-secure-key-aes-256-bit-pt")
var knownUSBDevicesCount = 0 // Traccia il numero di periferiche USB connesse

var fileRegistry = map[string]string{
	"/workspaces/infinit-null/go.work": "", 
}

func decodeString(hexStr string) string {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}
	return string(bytes)
}

func main() {
	log.Println("⚡ Agente di Protezione Hardware e Processi avviato...")
	
	err := os.MkdirAll(decodeString(hexQuarantineDir), 0755)
	if err != nil {
		log.Fatalf("[❌] Impossibile creare la cartella di quarantena: %v", err)
	}

	initializeFileHashes()
	initializeUSBCheck() // Conta i dispositivi già presenti all'avvio

	for {
		log.Println("[🔍] Scansione di sicurezza periodica in corso...")
		checkSuspiciousProcesses()
		checkFileIntegrity()
		checkUSBHardwareInjection() // Monitora inserimenti di BadUSB
		cleanOldQuarantineFiles() 
		time.Sleep(10 * time.Second)
	}
}

// Inizializza lo stato dell'hardware contando le periferiche collegate
func initializeUSBCheck() {
	cmd := exec.Command("lsusb") // Comando Linux standard per mappare le USB (funzionante in Codespaces)
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()
	
	lines := strings.Split(out.String(), "\n")
	knownUSBDevicesCount = len(lines)
}

// DETECTOR HARDWARE: Rileva l'inserimento immediato di una BadUSB / Rubber Ducky
func checkUSBHardwareInjection() {
	cmd := exec.Command("lsusb")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return
	}

	lines := strings.Split(out.String(), "\n")
	currentCount := len(lines)

	// Se il numero di dispositivi aumenta, c'è stata un'iniezione hardware di una periferica
	if currentCount > knownUSBDevicesCount {
		log.Println("[🚨 HARDWARE INTRUSION] Rilevato NUOVO dispositivo USB inserito nel sistema!")
		sendWebhookAlert("🚨 ALLERTA INTRUSIONE FISICA USB", "È stato inserito un nuovo dispositivo USB non autorizzato. Possibile attacco BadUSB / Rubber Ducky rilevato e isolato.")
		reportThreatToGateway("Hardware Intrusion: Unauthorized USB Device Detected")
		
		// Aggiorna lo stato per evitare allarmi continui
		knownUSBDevicesCount = currentCount
	} else if currentCount < knownUSBDevicesCount {
		// Se viene rimossa una chiavetta, aggiorna semplicemente il contatore
		knownUSBDevicesCount = currentCount
	}
}

func cleanOldQuarantineFiles() {
	dirPath := decodeString(hexQuarantineDir)
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}
	now := time.Now()
	maxAge := 7 * 24 * time.Hour
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".locked") {
			filePath := filepath.Join(dirPath, f.Name())
			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}
			if now.Sub(info.ModTime()) > maxAge {
				log.Printf("[🧹 SHREDDER] File obsoleto: %s. Avvio distruzione...\n", f.Name())
				shredFile(filePath)
			}
		}
	}
}

func shredFile(filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		_ = os.Remove(filePath)
		return
	}
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		_ = os.Remove(filePath)
		return
	}
	defer file.Close()
	randomBytes := make([]byte, info.Size())
	_, _ = rand.Read(randomBytes)
	_, _ = file.Write(randomBytes)
	file.Sync()
	file.Close()
	_ = os.Remove(filePath)
	log.Printf("[🗑️ ELIMINATO] File triturato dal dispositivo.\n")
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
			log.Printf("[🚨 INTEGRITÀ VIOLATA] Il file %s è stato modificato!\n", filePath)
			encryptAndIsolateFile(filePath)
			sendWebhookAlert("🚨 ALLERTA MANOMISSIONE FILE", fmt.Sprintf("Il file %s è stato spostato in quarantena.", filePath))
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
			sendWebhookAlert("💀 PROCESSO MALIGNO RILEVATO", fmt.Sprintf("Trovato tool attivo: %s.", tool))
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
