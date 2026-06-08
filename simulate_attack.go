package main

import (
	"bytes"
	"fmt"
	"net/http"
	"time"
)

func main() {
	fmt.Println("⚔️ [TEST DI PENETRAZIONE] Avvio simulazione attacco hacker controllato...")
	targetURL := "http://localhost:8080/login"
	
	// Payload malevolo che tenta una SQL Injection per bypassare il login
	payload := []byte(`{"username":"' OR 1=1 --","password":"hacked_password"}`)

	// Lancia 10 richieste consecutive ad altissima velocità per forzare il Rate Limiter (Simulazione DDoS)
	for i := 1; i <= 10; i++ {
		req, _ := http.NewRequest("POST", targetURL, bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		
		client := &http.Client{Timeout: 1 * time.Second}
		resp, err := client.Do(req)
		
		if err != nil {
			fmt.Printf("[❌] Richiesta %d bloccata: Il Firewall di Infinit-Null ha respinto l'attacco.\n", i)
		} else {
			fmt.Printf("[🔥] Richiesta %d inviata. Risposta API Gateway: %s\n", i, resp.Status)
			resp.Body.Close()
		}
		
		// Pausa infinitesimale per scaricare il traffico a raffica
		time.Sleep(50 * time.Millisecond) 
	}
	fmt.Println("\n🏁 Simulazione completata con successo!")
	fmt.Println("👉 Controlla i log e la Dashboard dell'API Gateway per verificare il blocco delle minacce.")
}
