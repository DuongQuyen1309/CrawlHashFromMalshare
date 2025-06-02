package db

import (
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
)

var DB *bun.DB

func ConnectDB() error {
	dns := "postgres://postgres:mysecretpassword@localhost:5432/postgres?sslmode=disable"
	pgdb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dns)))
	if err := pgdb.Ping(); err != nil {
		fmt.Println("Failed to connect to database:", err)
		return err
	}
	fmt.Println("Connected to database")
	DB = bun.NewDB(pgdb, pgdialect.New())
	DB.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
	return nil
}
