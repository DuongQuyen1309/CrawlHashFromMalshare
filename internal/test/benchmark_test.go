package test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/db"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/handler"
	"github.com/gin-gonic/gin"
)

func BenchmarkSearchRecordByDate(b *testing.B) {
	db.ConnectDB()

	var totalTime time.Duration

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/records/searchByDate?date=2019-03-19", nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		start := time.Now()
		handler.SearchRecordByDate(c)
		elapsed := time.Since(start)
		totalTime += elapsed
	}

	avg := totalTime / time.Duration(b.N)
	b.ReportMetric(float64(avg.Microseconds()), "µs/op")

}
