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
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const hexGatewayURL = "687474703a2f2f6c6f63616c686f73743a383038302f70726f746563746564" 
const hexBotToken = "494c5f54554f5f4a57545f544f4b454e5f515549"                       
const hexQuarantineDir = "2f776f726b7370616365732f696e66696e69742d6e756c6c2f71756172616e74696e65" 
const hexWebhookURL = "68747470733a2f2f6874747062696e2e6f72672f706f7374"               

var obfuscatedCryptoKey = []byte{0x2b, 0x31, 0x2a, 0x3d, 0x35, 0x3b, 0x2b, 0x3d, 0x3d, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x23, 0x32, 0x3d}
const xorMask byte = 0x4A 

var knownUSBDevicesCount = 0 
var fileRegistry = map[string]string{
	"/workspaces/infinit-null/go.work": "", 
}

func decodeString(hexStr string) string {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil { return "" }
	return string(bytes)
}

func getDecryptedKey() []byte {
	realKey := make([]byte, len(obfuscatedCryptoKey))
	for i := 0; i < len(obfuscatedCryptoKey); i++ {
		realKey[i] = obfuscatedCryptoKey[i] ^ xorMask
	}
	return realKey
}

func main() {
	log.Println("⚡ Agente di Protezione Integrale INDISTRUTTIBILE avviato...")
	
	// 🛡️ MODULO ANTI-TERMINATION: Intercetta i tentativi di spegnimento/kill
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	
	go func() {
		for sig := range sigChan {
			log.Printf("[🚨 ANTI-TERMINATION] Rilevato tentativo illegittimo di spegnimento tramite segnale: %v! RICHIESTA RESPINTA.\n", sig)
			sendWebhookAlert("🚨 TENTATIVO DI SPEGNIMENTO AGENTE", fmt.Sprintf("Un processo o utente ha provato a killare il Bot Client inviando il segnale %v. L'agente ha bloccato l'azione.", sig))
			reportThreatToGateway("Anti-Termination: Unauthorized Shutdown Attempt " + sig.String())
		}
	}()

	err := os.MkdirAll(decodeString(hexQuarantineDir), 0755)
	if err != nil { log.Fatalf("[❌] Impossibile creare la cartella di quarantena: %v", err) }

	initializeFileHashes()
	initializeUSBCheck() 

	for {
		log.Println("[🔍] Scansione di sicurezza periodica in corso...")
		checkSuspiciousProcesses()
		checkFileIntegrity()
		checkUSBHardwareInjection() 
		checkNetworkIntrusions() 
		checkHiddenRootkitProcesses() 
		checkTimeTampering() 
		cleanOldQuarantineFiles() 
		time.Sleep(10 * time.Second)
	}
}

func checkTimeTampering() {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://worldtimeapi.org")
	if err != nil { return }
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil { return }
	unixtimeStr := fmt.Sprintf("%v", data["unixtime"])
	realUnixTime, err := strconv.ParseInt(strings.Split(unixtimeStr, "."), 10, 64)
	if err != nil { return }
	localUnixTime := time.Now().Unix()
	diffMinutes := math.Abs(float64(localUnixTime-realUnixTime)) / 60.0
	if diffMinutes > 5.0 {
		log.Printf("[🚨 TIME TAMPERING] Sfasamento orologio! Differenza: %.1f minuti\n", diffMinutes)
		sendWebhookAlert("🚨 MANOMISSIONE ORA DI SISTEMA", fmt.Sprintf("L'orologio differisce di %.1f minuti. Attacco elusione scadenze.", diffMinutes))
		reportThreatToGateway(fmt.Sprintf("Time Tampering Detected: Clock skew of %.1f minutes", diffMinutes))
	}
}

func encryptAndIsolateFile(filePath string) {
	plaintext, err := os.ReadFile(filePath)
	if err != nil { _ = os.Remove(filePath); return }
	realAESKey := getDecryptedKey()
	block, err := aes.NewCipher(realAESKey)
	if err != nil { return }
	defer func() {
		for i := range realAESKey { realAESKey[i] = 0 }
	}()
	gcm, err := cipher.NewGCM(block)
	if err != nil { return }
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return }
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	fileName := filepath.Base(filePath)
	destination := filepath.Join(decodeString(hexQuarantineDir), fileName+".locked")
	_ = os.WriteFile(destination, ciphertext, 0644)
	_ = os.Remove(filePath)
	log.Printf("[🔒 CRYPTO-QUARANTENA] File cifrato con chiave protetta da XOR e isolato.\n")
}

func checkHiddenRootkitProcesses() {
	cmd := exec.Command("ps", "-e", "-o", "pid")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil { return }
	visiblePIDs := make(map[string]bool)
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		pid := strings.TrimSpace(line)
		if pid != "" && pid != "PID" { visiblePIDs[pid] = true }
	}
	procDir, err := os.Open("/proc")
	if err != nil { return }
	defer procDir.Close()
	dirs, err := procDir.Readdirnames(0)
	if err != nil { return }
	for _, name := range dirs {
		if _, err := strconv.Atoi(name); err == nil {
			if !visiblePIDs[name] {
				log.Printf("[🚨 ROOTKIT DETECTED] Processo nascosto! PID: %s\n", name)
				sendWebhookAlert("🚨 ATTACCO ROOTKIT CRITICO", fmt.Sprintf("Processo maligno nascosto rilevato. PID: %s.", name))
				reportThreatToGateway("Rootkit Intrusion: Hidden Process PID " + name)
			}
		}
	}
}

func checkNetworkIntrusions() {
	cmd := exec.Command("ss", "-tlnp")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil { return }
	outputStr := out.String()
	dangerousPorts := []string{":4444", ":666", ":9999"}
	for _, port := range dangerousPorts {
		if strings.Contains(outputStr, port) {
			log.Printf("[🚨 INTRUSIONE DI RETE] Porta sospetta aperta: %s!\n", port)
			sendWebhookAlert("🚨 ALLERTA BACKDOOR DI RETE", fmt.Sprintf("Rilevata porta aperta non autorizzata: %s.", port))
			reportThreatToGateway("Network Intrusion: Suspicious Port Listening " + port)
		}
	}
}

func initializeUSBCheck() {
	cmd := exec.Command("lsusb") 
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()
	lines := strings.Split(out.String(), "\n")
	knownUSBDevicesCount = len(lines)
}

func checkUSBHardwareInjection() {
	cmd := exec.Command("lsusb")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil { return }
	lines := strings.Split(out.String(), "\n")
	currentCount := len(lines)
	if currentCount > knownUSBDevicesCount {
		log.Println("[🚨 HARDWARE INTRUSION] Nuovo dispositivo USB inserito!")
		sendWebhookAlert("🚨 ALLERTA INTRUSIONE FISICA USB", "Dispositivo USB non autorizzato rilevato.")
		reportThreatToGateway("Hardware Intrusion: Unauthorized USB Device Detected")
		knownUSBDevicesCount = currentCount
	} else if currentCount < knownUSBDevicesCount {
		knownUSBDevicesCount = currentCount
	}
}

func cleanOldQuarantineFiles() {
	dirPath := decodeString(hexQuarantineDir)
	files, err := os.ReadDir(dirPath)
	if err != nil { return }
	now := time.Now()
	maxAge := 7 * 24 * time.Hour
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".locked") {
			filePath := filepath.Join(dirPath, f.Name())
			info, err := os.Stat(filePath)
			if err != nil { continue }
			if now.Sub(info.ModTime()) > maxAge { shredFile(filePath) }
		}
	}
}

func shredFile(filePath string) {
	info, err := os.Stat(filePath)
	if err != nil { _ = os.Remove(filePath); return }
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil { _ = os.Remove(filePath); return }
	defer file.Close()
	randomBytes := make([]byte, info.Size())
	_, _ = rand.Read(randomBytes)
	_, _ = file.Write(randomBytes)
	file.Sync()
	file.Close()
	_ = os.Remove(filePath)
}

func initializeFileHashes() {
	for filePath := range fileRegistry {
		hash, err := calculateFileHash(filePath)
		if err == nil { fileRegistry[filePath] = hash }
	}
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil { return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil { return "", err }
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func checkFileIntegrity() {
	for filePath, oldHash := range fileRegistry {
		currentHash, err := calculateFileHash(filePath)
		if err != nil { continue }
		if oldHash != "" && currentHash != oldHash {
			log.Printf("[🚨 INTEGRITÀ VIOLATA] Il file %s è stato modificato!\n", filePath)
			encryptAndIsolateFile(filePath)
			sendWebhookAlert("🚨 ALLERTA MANOMISSIONE FILE", fmt.Sprintf("Il file %s è stato spostato in quarantena.", filePath))
			reportThreatToGateway("File Tampering & Encrypted Quarantine: " + filePath)
			fileRegistry[filePath] = currentHash
		}
	}
}

func sendWebhookAlert(title, message string) {
	payload := map[string]interface{}{
		"username": "Security Bot Agent",
		"content":  fmt.Sprintf("**%s**\n📅 *Data:* %s\n💬 *Dettagli:* %s", title, time.Now().Format("2006-01-02 15:04:05"), message),
	}
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(decodeString(hexWebhookURL), "application/json", bytes.NewBuffer(jsonData))
	if err != nil { return }
	defer resp.Body.Close()
}

func checkSuspiciousProcesses() {
	cmd := exec.Command("ps", "aux")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil { return }
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
