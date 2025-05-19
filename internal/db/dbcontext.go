package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/model"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/extra/bundebug"
)

var DB *bun.DB

func ConnectDB() {
	dns := "postgres://postgres:mysecretpassword@localhost:5432/postgres?sslmode=disable"
	pgdb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dns)))
	if err := pgdb.Ping(); err != nil {
		fmt.Println("Failed to connect to database:", err)
		return
	}
	fmt.Println("Connected to database")
	DB = bun.NewDB(pgdb, pgdialect.New())
	DB.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
}
func CreateEntity() {
	ctx := context.Background()
	if _, err := DB.NewCreateTable().Model((*model.Example)(nil)).IfNotExists().Exec(ctx); err != nil {
		fmt.Println("Error creating table:", err)
		return
	}
	_, _ = DB.Exec(`ALTER TABLE example2s 
					ALTER COLUMN date TYPE date USING date::date,
					ALTER COLUMN id TYPE int USING id::int,
					ALTER COLUMN md5 TYPE text,
					ALTER COLUMN sha1 TYPE text,
					ALTER COLUMN sha256 TYPE text`)

}
func CreateVirusHashEntity() {
	ctx := context.Background()
	if _, err := DB.NewCreateTable().Model((*model.VirusHash)(nil)).IfNotExists().Exec(ctx); err != nil {
		fmt.Println("Error creating table:", err)
		return
	}
	_, err := DB.Exec(`
		ALTER TABLE virus_hashes
		ALTER COLUMN date TYPE date USING date::date,
		ALTER COLUMN last_analysis_stats TYPE jsonb USING last_analysis_stats::jsonb,
		ALTER COLUMN total_votes TYPE jsonb USING total_votes::jsonb
	`)
	if err != nil {
		fmt.Println("Error altering table:", err)
	}
}

func AppendColumnTransactionTable(DB *bun.DB) {
	_, err := DB.Exec(`ALTER TABLE example2s ADD COLUMN IF NOT EXISTS is_delete boolean`)
	if err != nil {
		fmt.Println(err)
	}
}
