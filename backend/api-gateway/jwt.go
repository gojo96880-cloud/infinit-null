package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

var jwtSecret = []byte("super-segreto-chiave-cybersecurity-2026")

func GenerateToken(username string) (string, error) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pStr := fmt.Sprintf(`{"sub":"%s","exp":%d}`, username, time.Now().Add(time.Hour).Unix())
	p := base64.RawURLEncoding.EncodeToString([]byte(pStr))

	unsignedToken := h + "." + p

	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(unsignedToken))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsignedToken + "." + signature, nil
}

func ValidateToken(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", errors.New("formato token invalido")
	}

	unsignedToken := parts[0] + "." + parts[1]

	mac := hmac.New(sha256.New, jwtSecret)
	mac.Write([]byte(unsignedToken))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if parts[2] != expectedSignature {
		return "", errors.New("firma token non valida (manomissione!)")
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	return string(decodedPayload), nil
}
