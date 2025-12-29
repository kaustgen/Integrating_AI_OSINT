// Author: Kaleb Austgen
// Date Created: 12/28/25
// Purpose: Database initialization and schema definition

package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func InitDB(filepath string) *sql.DB {
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	// Create tables
	if _, err := db.Exec(Schema); err != nil {
		log.Fatal(err)
	}

	return db
}
