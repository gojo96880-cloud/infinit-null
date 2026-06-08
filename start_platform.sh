#!/bin/bash

# Colori per il terminale
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0;3m' # Nessun colore

echo -e "${BLUE}=============================================================${NC}"
echo -e "${BLUE}    AVVIO ORCHESTRATORE INFINIT-NULL CYBERSECURITY PLATFORM  ${NC}"
echo -e "${BLUE}=============================================================${NC}"

# 1. Controllo ambiente Go Workspace
if [ ! -f "go.work" ]; then
    echo -e "${RED}[❌] Errore: Esegui lo script dalla cartella principale del progetto!${NC}"
    exit 1
fi

# 2. Avvio dell'API Gateway (Server)
echo -e "${GREEN}[🚀] Avvio del server API Gateway in background...${NC}"
cd api-gateway
GOWORK=off go run . > gateway.log 2>&1 &
GATEWAY_PID=$!
cd ..

# Attende un istante per far attivare la porta
time.Sleep 2

# 3. Avvio del Bot Client Agent (Protezione Hardware/Kernel)
echo -e "${GREEN}[🤖] Avvio del Bot Client Agent in background...${NC}"
cd backend
GOWORK=off go run bot_go.go > bot.log 2>&1 &
BOT_PID=$!
cd ..

echo -e "${BLUE}-------------------------------------------------------------${NC}"
echo -e "${GREEN}[✅] TUTTI I SISTEMI SONO ATTIVI E IN ASCOLTO LIVE!${NC}"
echo -e "[📋] PID API Gateway: $GATEWAY_PID (Log salvati in api-gateway/gateway.log)"
echo -e "[📋] PID Bot Agent:  $BOT_PID (Log salvati in backend/bot.log)"
echo -e "${BLUE}-------------------------------------------------------------${NC}"
echo -e "👉 Per testare il Firewall, usa: ${GREEN}go run simulate_attack.go${NC}"
echo -e "👉 Per spegnere tutti i servizi, usa: ${RED}kill $GATEWAY_PID $BOT_PID${NC}"
echo -e "${BLUE}=============================================================${NC}"
