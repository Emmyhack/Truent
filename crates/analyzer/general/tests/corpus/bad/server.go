// EXPECT: gen_command_injection
// EXPECT: gen_tls_verification_disabled
// EXPECT: gen_sql_injection
package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
)

func ping(host string) {
	exec.Command("sh", "-c", fmt.Sprintf("ping -c 1 %s", host)).Run()
}

func insecure() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

func user(db *sql.DB, name string) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}
