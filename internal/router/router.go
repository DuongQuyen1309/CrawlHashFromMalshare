package router

import (
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/handler"
	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	router := gin.Default()
	router.DELETE("/records/:date", handler.DeleteRecordByDate)
	router.GET("/records", handler.GetAllRecords)
	router.GET("/records/:date", handler.SearchRecordByDate)
	router.GET("/records/:date/:category", handler.GetHashesByDateAndCategory)
	// router.GET("/virusHashs/:hash", handler.SearchSuspectVirusHashByHash)
	// router.GET("/records/:date/:category", handler.ParseHashByDateCategory)
	router.Run(":8080")
	return router
}
