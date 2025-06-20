package main

import (
	// "context"

	// "github.com/DuongQuyen1309/crawlhashfrommalshare/internal/datastore"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/db"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/router"
	// "github.com/DuongQuyen1309/crawlhashfrommalshare/internal/service"
)

func main() {
	// ctx := context.Background()
	if err := db.ConnectDB(); err != nil {
		return
	}
	// if err := datastore.CreateEntity(); err != nil {
	// 	return
	// }
	// if err := datastore.CreateVirusHashEntity(); err != nil {
	// 	return
	// }
	router := router.SetupRouter()
	router.Run(":8080")
	// err := service.CrawlData(ctx)
	// if err != nil {
	// 	return
	// }
}
