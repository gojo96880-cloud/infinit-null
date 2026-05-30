package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// LogSicurezza definisce la struttura dei dati inviati al SIEM centrale
type LogSicurezza struct {
	Timestamp   string `json:"timestamp"`
	Dispositivo string `json:"dispositivo"`
	TipoEvento  string `json:"tipo_evento"` // "PROCESSI", "INTEGRITA_FILE"
	Dettagli    string `json:"dettagli"`
	Stato       string `json:"stato"`       // "OK", "ANOMALIA"
}

func inviaLogAlGateway(logData LogSicurezza) {
	urlGateway := "http://localhost:8080/api/v1/threats/"
	
	jsonData, err := json.Marshal(logData)
	if err != nil {
		log.Printf("Errore di codifica JSON: %v", err)
		return
	}

	resp, err := http.Post(urlGateway, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Gateway non raggiungibile (Server spento o offline): %v", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[CLIENT] Log inviato con successo. Risposta server: %s\n", resp.Status)
}

// Analizza un file reale sul sistema e ne calcola l'hash SHA-256 per verificare che non sia alterato
func analizzaFileIntegrita(percorsoFile string) string {
	file, err := os.Open(percorsoFile)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func monitoraSistema() {
	fmt.Println("[MONITOR] Avvio scansione attiva del dispositivo...")

	// Esempio di monitoraggio integrità su un file critico di sistema
	// Nota: Su Windows reale monitorerà file come "C:\\Windows\\System32\\drivers\\etc\\hosts"
	percorsoTest := "go.mod" 
	hashOttenuto := analizzaFileIntegrita(percorsoTest)

	dettagliMsg := fmt.Sprintf("Verifica file [%s]. Hash calcolato: %s", percorsoTest, hashOttenuto)
	
	logData := LogSicurezza{
		Timestamp:   time.Now().Format(time.RFC3339),
		Dispositivo: "Endpoint-Windows-User",
		TipoEvento:  "INTEGRITA_FILE",
		Dettagli:    dettagliMsg,
		Stato:       "OK",
	}

	if hashOttenuto == "" {
		logData.Dettagli = fmt.Sprintf("Allerta: Impossibile accedere al file critico %s o file rimosso!", percorsoTest)
		logData.Stato = "ANOMALIA"
	}

	inviaLogAlGateway(logData)
}

func main() {
	fmt.Println("====================================================")
	fmt.Println(" CORE AGENT AVVIATO: MONITORAGGIO INTEGRITÀ ATTIVO ")
	fmt.Println("====================================================")

	// Esegue il controllo di sicurezza continuo ogni 15 secondi
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		monitoraSistema()
	}
}
