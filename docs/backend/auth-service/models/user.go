package models

import (
	"time"
)

type User struct {
	ID         int64     `db:"id" json:"id"`
	Username   string    `db:"username" json:"username"`
	Email      string    `db:"email" json:"email"`
	Password   string    `db:"password_hash" json:"-"`
	MFAEnabled bool      `db:"mfa_enabled" json:"mfa_enabled"`
	MFASecret  string    `db:"mfa_secret" json:"-"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`
	DeletedAt  *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type Token struct {
	ID        int64     `db:"id" json:"id"`
	UserID    int64     `db:"user_id" json:"user_id"`
	TokenHash string    `db:"token_hash" json:"-"`
	TokenType string    `db:"token_type" json:"token_type"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

type AuditLog struct {
	ID        int64      `db:"id" json:"id"`
	UserID    *int64     `db:"user_id" json:"user_id"`
	Action    string     `db:"action" json:"action"`
	Resource  *string    `db:"resource" json:"resource"`
	Status    string     `db:"status" json:"status"`
	IPAddress string     `db:"ip_address" json:"ip_address"`
	UserAgent string     `db:"user_agent" json:"user_agent"`
	Details   string     `db:"details" json:"details"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

type Role struct {
	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`
}

type Permission struct {
	ID          int64  `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`
}
