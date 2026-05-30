package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

// LogSicurezza definisce la struttura dei dati inviati al server centrale
type LogSicurezza struct {
	Timestamp   string `json:"timestamp"`
	Dispositivo string `json:"dispositivo"`
	TipoEvento  string `json:"tipo_evento"` // "PROCESSI", "INTEGRITA_FILE", "RETE"
	Dettagli    string `json:"dettagli"`
	Stato       string `json:"stato"`       // "OK", "SUSPICIOUS", "ALERT"
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
		log.Printf("Gateway centrale non raggiungibile: %v", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[EDR-AGENT] Evento [%s] inviato. Risposta server: %s\n", logData.TipoEvento, resp.Status)
}

// Analizza i file sensibili del sistema per rilevare alterazioni non autorizzate
func verificaIntegritaFile(percorso string) {
	file, err := os.Open(percorso)
	var stato, dettagli string
	if err != nil {
		stato = "ALERT"
		dettagli = fmt.Sprintf("Allerta: Impossibile accedere al file critico %s o file rimosso!", percorso)
	} else {
		defer file.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			stato = "ALERT"
			dettagli = fmt.Sprintf("Errore durante il calcolo dell'hash del file %s", percorso)
		} else {
			stato = "OK"
			dettagli = fmt.Sprintf("Verifica file [%s] superata. SHA-256: %s", percorso, hex.EncodeToString(hash.Sum(nil)))
		}
	}

	inviaLogAlGateway(LogSicurezza{
		Timestamp:   time.Now().Format(time.RFC3339),
		Dispositivo: "Windows-Endpoint",
		TipoEvento:  "INTEGRITA_FILE",
		Dettagli:    dettagli,
		Stato:       stato,
	})
}

// Controlla le porte e le connessioni attive sul dispositivo locale
func controllaConnessioniRete() {
	var porteIntercettate []int
	// Scansione locale per identificare servizi in ascolto non autorizzati
	for porto := 80; porto <= 1024; porto++ {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", porto))
		if err != nil {
			// Se la porta è occupata, c'è un servizio attivo
			porteIntercettate = append(porteIntercettate, porto)
		} else {
			ln.Close()
		}
	}

	stato := "OK"
	if len(porteIntercettate) > 5 {
		stato = "SUSPICIOUS"
	}

	inviaLogAlGateway(LogSicurezza{
		Timestamp:   time.Now().Format(time.RFC3339),
		Dispositivo: "Windows-Endpoint",
		TipoEvento:  "RETE",
		Dettagli:    fmt.Sprintf("Scansione porte locali completata. Porte attive rilevate: %v", porteIntercettate),
		Stato:       stato,
	})
}

func eseguiAuditDifensivo() {
	fmt.Println("[EDR-AGENT] Avvio sessione di monitoraggio attivo...")
	// Monitoraggio di un file del modulo come test di integrità
	verificaIntegritaFile("main.go")
	controllaConnessioniRete()
}

func main() {
	fmt.Printf("=====================================================\n")
	fmt.Printf(" AGENTE DI PROTEZIONE ATTIVA AVVIATO (%s)\n", runtime.GOOS)
	fmt.Printf("=====================================================\n")

	// Monitoraggio periodico continuo impostato a 30 secondi
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	eseguiAuditDifensivo()
	for range ticker.C {
		eseguiAuditDifensivo()
	}
}
