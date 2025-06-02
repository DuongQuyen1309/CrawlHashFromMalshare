package datastore

import (
	"context"
	"fmt"
	"time"

	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/db"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/model"
)

const (
	DATE_PATTERN = "2006-01-02"
)

func CreateEntity() error {
	ctx := context.Background()
	if _, err := db.DB.NewCreateTable().Model((*model.Example)(nil)).IfNotExists().Exec(ctx); err != nil {
		fmt.Println("Error creating table:", err)
		return err
	}
	if _, err := db.DB.NewCreateIndex().
		Model((*model.Example)(nil)).
		Index("idx_date").
		Column("date").
		Unique().
		IfNotExists().
		Exec(ctx); err != nil {
		return err
	}

	if _, err := db.DB.Exec(`ALTER TABLE example2s 
					ALTER COLUMN date TYPE date USING date::date,
					ALTER COLUMN id TYPE int USING id::int,
					ALTER COLUMN md5 TYPE text,
					ALTER COLUMN sha1 TYPE text,
					ALTER COLUMN sha256 TYPE text`); err != nil {
		return err
	}
	return nil
}

func DeleteHashById(id int, c context.Context) error {
	_, err := db.DB.NewUpdate().Model((*model.Example)(nil)).Where("id = ?", id).Set("is_delete = true").Exec(c)
	if err != nil {
		return err
	}
	return nil
}

func GetHashByDate(date time.Time, record *model.Example, c context.Context) error {
	err := db.DB.NewSelect().Model(record).
		Where("date = ? and is_delete is not true", date.Format(DATE_PATTERN)).
		Scan(c)
	if err != nil {
		return err
	}
	return nil
}
func DeleteHashByDate(date time.Time, c context.Context) error {
	_, err := db.DB.NewUpdate().Model((*model.Example)(nil)).
		Where("date = ?", date.Format(DATE_PATTERN)).
		Set("is_delete = true").Exec(c)
	if err != nil {
		return err
	}
	return nil
}

func TakeRecordByAttribute(record *model.Example, date time.Time, c context.Context) {
	err := db.DB.NewSelect().
		Model(record).
		Where("date::date = ?", date.Format(DATE_PATTERN)).
		Scan(c)
	if err != nil {
		fmt.Println("Error not found:", err)
	}
}
