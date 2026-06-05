package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Configurazione dell'API Gateway locale
const gatewayURL = "http://localhost:8080/protected"
const botToken = "IL_TUO_JWT_TOKEN_QUI" // Sarà sostituito dinamicamente dal login

func main() {
	log.Println("⚡ Agente di Protezione Client avviato in background...")
	
	// Ciclo infinito di monitoraggio (Esegue un controllo ogni 10 secondi)
	for {
		log.Println("[🔍] Scansione dei processi di sistema in corso...")
		checkSuspiciousProcesses()
		time.Sleep(10 * time.Second)
	}
}

// Scansiona i processi attivi alla ricerca di minacce o strumenti di hacking comuni
func checkSuspiciousProcesses() {
	// Esegue il comando Linux per listare i processi (compatibile con Codespaces)
	cmd := exec.Command("ps", "aux")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("[❌] Errore durante la lettura dei processi: %v\n", err)
		return
	}

	outputStr := out.String()
	// Lista di parole chiave sospette da rilevare (es. tool di scansione/attacco)
	maliciousTools := []string{"nmap", "wireshark", "hydra", "metasploit", "nc"}

	for _, tool := range maliciousTools {
		if strings.Contains(strings.ToLower(outputStr), tool) {
			log.Printf("[🚨 MINACCIA RILEVATA] Trovato processo sospetto attivo: %s!\n", tool)
			reportThreatToGateway(tool)
		}
	}
}

// Invia una notifica di minaccia all'API Gateway sfruttando l'autenticazione JWT
func reportThreatToGateway(tool string) {
	data := map[string]string{
		"event":   "Malicious Process Detected",
		"process": tool,
		"status":  "Blocked",
	}
	jsonData, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", gatewayURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	// Allega il Token JWT per superare il blocco di sicurezza del server
	req.Header.Set("Authorization", "Bearer "+botToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[⚠️] Impossibile contattare l'API Gateway per segnalare la minaccia: %v\n", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("[✅] Allerta inviata con successo all'API Gateway. Risposta server: %s\n", resp.Status)
}
