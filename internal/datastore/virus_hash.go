package datastore

import (
	"context"
	"fmt"
	"time"

	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/db"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/model"
)

func CreateVirusHashEntity() error {
	ctx := context.Background()
	if _, err := db.DB.NewCreateTable().Model((*model.VirusHash)(nil)).IfNotExists().Exec(ctx); err != nil {
		fmt.Println("Error creating table:", err)
		return err
	}
	_, err := db.DB.Exec(`
		ALTER TABLE virus_hashes
		ALTER COLUMN date TYPE date USING date::date,
		ALTER COLUMN last_analysis_stats TYPE jsonb USING last_analysis_stats::jsonb,
		ALTER COLUMN total_votes TYPE jsonb USING total_votes::jsonb
	`)
	if err != nil {
		fmt.Println("Error altering table:", err)
		return err
	}
	_, err = db.DB.NewCreateIndex().
		Model((*model.VirusHash)(nil)).
		Index("idx_hash").
		Column("hash").
		Unique().
		IfNotExists().
		Exec(ctx)
	if err != nil {
		return err
	}

	return nil
}

func GetVirusHashByHash(hash string, c context.Context) (model.VirusHash, error) {
	var record model.VirusHash
	err := db.DB.NewSelect().Model(&record).Where("hash = ?", hash).Scan(c)
	if err != nil {
		return model.VirusHash{}, err
	}
	return record, nil
}
func GetVirusHashByDateAndCategory(date time.Time, category string, c context.Context) ([]model.VirusHash, error) {
	var records []model.VirusHash
	_, err := db.DB.NewSelect().Model(&records).
		Where("date::date = ? and category = ?", date, category).
		Offset(0).
		Limit(10).
		Exec(c)
	if err != nil {
		return nil, err
	}
	return records, nil
}
func InsertVirusData(virusRecord *model.VirusHash, c context.Context) error {
	_, err := db.DB.NewInsert().Model(virusRecord).Exec(context.Background())
	if err != nil {
		fmt.Println("Error insert virus record:", err)
		return err
	}
	return nil
}
