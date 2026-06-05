package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
const quarantineDir = "/workspaces/infinit-null/quarantine"

// Chiave simmetrica a 32 byte per la cifratura AES-256 (In produzione va protetta)
var cryptoKey = []byte("cyber-secure-key-aes-256-bit-pt")

var fileRegistry = map[string]string{
	"/workspaces/infinit-null/go.work": "", 
}

func main() {
	log.Println("⚡ Agente di Protezione Crittografica Client avviato...")
	
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
			
			// Chiama la nuova funzione che cifra e isola il file
			encryptAndIsolateFile(filePath)

			reportThreatToGateway("File Tampering & Encrypted Quarantine: " + filePath)
			fileRegistry[filePath] = currentHash
		}
	}
}

// Funzione avanzata: legge il file, lo cifra in AES e lo salva in quarantena
func encryptAndIsolateFile(filePath string) {
	// 1. Legge il contenuto del file infetto
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("[❌] Impossibile leggere il file per cifratura: %v. Rimuovo direttamente.\n", err)
		_ = os.Remove(filePath)
		return
	}

	// 2. Inizializza il cifrario AES
	block, err := aes.NewCipher(cryptoKey)
	if err != nil {
		log.Printf("[❌] Errore inizializzazione AES: %v\n", err)
		return
	}

	// 3. Genera un vettore di inizializzazione (IV) casuale
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[❌] Errore GCM: %v\n", err)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("[❌] Errore generazione nonce: %v\n", err)
		return
	}

	// 4. Cifra i dati
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// 5. Salva il file cifrato in quarantena
	fileName := filepath.Base(filePath)
	destination := filepath.Join(quarantineDir, fileName+".locked")
	
	err = os.WriteFile(destination, ciphertext, 0644)
	if err != nil {
		log.Printf("[❌] Scrittura file cifrato fallita: %v\n", err)
		return
	}

	// 6. Elimina il file originale non sicuro dal PC
	_ = os.Remove(filePath)
	log.Printf("[🔒 CRYPTO-QUARANTENA] Il file %s è stato cifrato in AES-256 e neutralizzato in: %s\n", fileName, destination)
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
