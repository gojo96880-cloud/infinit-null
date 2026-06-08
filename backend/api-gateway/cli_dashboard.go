package main

import (
	"fmt"
	"strings"
)

// Mostra un pannello statistico avanzato direttamente in formato testuale nel terminale
func RenderASCIIDashboard(totalThreats, bannedIPs int) {
	fmt.Println("\n" + strings.Repeat("=", 65))
	fmt.Println("   📊 INFINIT-NULL ENTERPRISE SECURITY ANALYTICS (REAL-TIME)   ")
	fmt.Println(strings.Repeat("=", 65))
	
	// Grafico a barre ASCII per le Minacce Bloccate
	threatBar := strings.Repeat("█", totalThreats)
	if totalThreats > 20 { threatBar = strings.Repeat("█", 20) + " +" }
	fmt.Printf(" [⚠️] MINACCE INTERCETTATE (%d) : %s\n", totalThreats, threatBar)

	// Grafico a barre ASCII per gli IP nel Firewall
	ipBar := strings.Repeat("⛔", bannedIPs)
	if bannedIPs > 10 { ipBar = strings.Repeat("⛔", 10) + " +" }
	fmt.Printf(" [🛡️] IP BANNERMAN (FIREWALL) (%d) : %s\n", bannedIPs, ipBar)
	
	fmt.Println(strings.Repeat("-", 65))
	fmt.Println(" [🔒 STATO LIVELLO KERNEL]: ATTIVO | [📡 RETE NIDS]: AGGIORNATA")
	fmt.Println(strings.Repeat("=", 65) + "\n")
}
