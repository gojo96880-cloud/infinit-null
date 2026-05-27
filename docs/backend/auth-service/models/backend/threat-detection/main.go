package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

func main() {
	log.Println("Starting Threat Detection Service")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Threat Detection Service running on port 8002")

	select {}
}
