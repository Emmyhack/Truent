package main

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"os"
	"os/exec"
)

// Correct Go: placeholders, no shell, crypto/rand, TLS verified.
func user(db *sql.DB, id int) (*sql.Row, error) {
	return db.QueryRow("SELECT id, name FROM users WHERE id = $1", id), nil
}

func list(dir string) ([]byte, error) {
	return exec.Command("ls", "-la", dir).Output()
}

func token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func client() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func password() string {
	return os.Getenv("DB_PASSWORD")
}
