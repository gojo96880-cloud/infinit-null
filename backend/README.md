# 🛡️ Infinit-Null Enterprise Cybersecurity Platform

Piattaforma avanzata di livello industriale basata su un'architettura a **Microservizi in Go**, progettata per blindare l'integrità dei dispositivi hardware e gestire in totale autonomia il monitoraggio e l'isolamento delle minacce informatiche senza dipendere da interfacce browser aperte.

## 🎛️ Architettura Core

### 1. API Gateway (`/api-gateway`)
Il cuore pulsante del server. Implementa funzionalità di sicurezza enterprise:
- **Autenticazione reale**: Gestione sicura delle credenziali utenti tramite hash `Bcrypt` e rilascio di token di sessione firmati digitalmente `JWT`.
- **RBAC (Role-Based Access Control)**: Controllo degli accessi granulare basato sui ruoli (`admin` e `viewer`) per proteggere gli endpoint sensibili.
- **WAF & Anti-SQL Injection**: Sanificazione proattiva delle stringhe in ingresso per bloccare exploit speculativi sul database.
- **Protezione DDoS (Rate Limiting)**: Algoritmo di blocco automatico e ban permanente in database (`banned_ips`) dei mittenti recidivi.
- **Database Optimizzato & TTL**: Database SQLite con indici di ricerca rapidi e worker di manutenzione ciclica in background per la rimozione automatica dei log obsoleti dopo 30 giorni.
- **Backup Engine Cifrato**: Generazione quotidiana di copie speculari del database blindate tramite crittografia asimmetrica `AES-256`.

### 🤖 2. Bot Agent Client (`/backend`)
Demone permanente operante a basso livello sul dispositivo hardware:
- **Anti-Termination Monitoring**: Intercettazione dei segnali di kill di sistema (`SIGTERM`, `CTRL+C`) per impedire lo spegnimento abusivo dell'agente.
- **Anti-Rootkit Detection**: Ispezione diretta del kernel space (`/proc`) e controllo incrociato con i processi visibili per scovare malware nascosti.
- **NIDS (Network Intrusion Detection)**: Monitoraggio dei socket di rete per intercettare l'apertura abusiva di backdoor o porte silenti.
- **Monitoraggio Hardware (lsusb)**: Rilevamento in tempo reale di iniezioni hardware prodotte da chiavette maligne (BadUSB / Rubber Ducky).
- **Crypto-Quarantena & Shredder**: Isolamento istantaneo e cifratura dei file manomessi in `AES-256`, seguito da un processo di triturazione forense (`Shredding`) con dati casuali dopo 7 giorni.
- **Anti-Time Tampering**: Verifica continua dell'orologio di sistema tramite server orari esterni UTC sicuri per impedire l'elusione delle scadenze e dei controlli.
- **Webhook Push Notifications**: Invio automatico degli allarmi critici formattati in tempo reale su canali di ascolto amministrativi.

---
🚀 *Sviluppato con successo un passo alla volta.*
