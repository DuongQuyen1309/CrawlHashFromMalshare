package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/db"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/uptrace/bun"
)

const (
	DATE_PATTERN = "2006-01-02"
)

var ctx = context.Background()

func CallApi() {
	db.ConnectDB()
	db.CreateEntity()
	db.AppendColumnTransactionTable(db.DB)
	db.CreateVirusHashEntity()
	router := gin.Default()

	router.DELETE("/records/deleteByDate", DeleteRecordByDate)
	router.DELETE("records/deleteById", DeleteById)
	router.GET("/records/searchByDate", SearchRecordByDate)
	router.GET("/records/searchByHash", SearchSuspectVirusHashByHash)
	router.GET("/records/parseHash", ParseHashByDateCategory)
	router.Run(":8080")
}
func DeleteById(c *gin.Context) {
	id := c.Query("id")
	if _, err := strconv.Atoi(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not validated id"})
		return
	}
	_, err := db.DB.NewUpdate().Set("is_delete = true").Model((*model.Example)(nil)).Where("id = ?", id).Exec(ctx)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not found record"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Delete successfully"})
}
func SearchSuspectVirusHashByHash(c *gin.Context) {
	hash := c.Query("hash")
	var record model.VirusHash
	err := db.DB.NewSelect().Model(&record).Where("hash = ?", hash).Scan(ctx)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not found record"})
		return
	}
	c.JSON(http.StatusOK, record)

}
func SearchRecordByDate(c *gin.Context) {
	dateString := c.Query("date")
	date, err := time.Parse(DATE_PATTERN, dateString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format"})
		return
	}

	var record model.Example
	err = db.DB.NewSelect().
		Model(&record).
		Where("date::date = ?", date.Format(DATE_PATTERN)).
		Where("is_delete IS NOT TRUE").
		Scan(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No records found"})
		return
	}
	c.JSON(http.StatusOK, record)
}

func DeleteRecordByDate(c *gin.Context) {
	dateString := c.Query("date")
	date, err := time.Parse(DATE_PATTERN, dateString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not found"})
		return
	}
	_, err = db.DB.NewUpdate().Set("is_delete = true").Model((*model.Example)(nil)).Where("date::date = ?", date.Format(DATE_PATTERN)).Exec(ctx)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Record deleted successfully"})
}
func TakeRecordByAttribute(ctx context.Context, db *bun.DB, record *model.Example, date time.Time) {
	err := db.NewSelect().
		Model(record).
		Where("date::date = ?", date.Format(DATE_PATTERN)).
		Scan(ctx)
	if err != nil {
		fmt.Println("Error not found:", err)
	}
}
func convertMap(in map[string]interface{}) map[string]int {
	out := make(map[string]int)
	for k, v := range in {
		if f, ok := v.(float64); ok {
			out[k] = int(f)
		}
	}
	return out
}

func ParseHashByDateCategory(c *gin.Context) {
	dateString := c.Query("date")
	category := c.Query("category")
	if category != MD5_FILE && category != SHA1_FILE && category != SHA256_FILE {
		fmt.Println("Error category")
		return
	}
	date, err := time.Parse(DATE_PATTERN, dateString)
	if err != nil {
		fmt.Println("Error transform date")
		return
	}
	var record model.Example
	TakeRecordByAttribute(c, db.DB, &record, date)
	switch category {
	case MD5_FILE:
		md5 := record.Md5
		array := strings.Split(md5, "\n")
		if err := ProcessVirusData("md5", date, array); err != nil {
			fmt.Println(err)
			break
		}
	case SHA1_FILE:
		sha1 := record.Sha1
		array := strings.Split(sha1, "\n")
		if err := ProcessVirusData("sha1", date, array); err != nil {
			fmt.Println(err)
			break
		}
	case SHA256_FILE:
		sha256 := record.Sha256
		array := strings.Split(sha256, "\n")
		if err := ProcessVirusData("sha256", date, array); err != nil {
			fmt.Println(err)
			break
		}
	}
}

func ProcessVirusData(category string, date time.Time, array []string) error {
	for i := 0; i < len(array); i++ {
		virusData, errParse := ParseDataWithVirusTotal(array[i])
		if errParse != nil {
			fmt.Println(errParse)
			return errParse
		}
		errorInsert := InsertVirusData(virusData, array[i], date, category)
		if errorInsert != nil {
			fmt.Println(errorInsert)
			return errorInsert
		}
	}
	return nil
}
func ParseDataWithVirusTotal(hash string) (model.VirusApiResponse, error) {
	req, _ := http.NewRequest("GET", "https://www.virustotal.com/api/v3/files/"+hash, nil)
	req.Header.Set("x-apikey", "fa31be9cc448ae4c39862599ed203b66dbdd12d00b7568801d52c165893b7371")
	resp, err1 := http.DefaultClient.Do(req)
	if err1 != nil {
		fmt.Println("Error request api virustotal")
		return model.VirusApiResponse{}, err1
	}
	body, err2 := io.ReadAll(resp.Body)
	if err2 != nil {
		fmt.Println("Error read body")
		return model.VirusApiResponse{}, err2
	}
	var virusData model.VirusApiResponse
	if err3 := json.Unmarshal(body, &virusData); err3 != nil {
		fmt.Println("Error parse JSON")
		return model.VirusApiResponse{}, err3
	}
	return virusData, nil
}

func InsertVirusData(virusData model.VirusApiResponse, hash string, date time.Time, hashKind string) error {
	malValue1, _ := virusData.Data.Attributes.LastAnalysisStats["malicious"].(float64)
	malValue2, _ := virusData.Data.Attributes.TotalVotes["malicious"].(float64)
	if malValue1 >= 1 || malValue2 >= 1 {
		virusRecord := model.VirusHash{
			Hash:              hash,
			HashKind:          hashKind,
			Date:              date,
			LastAnalysisStats: convertMap(virusData.Data.Attributes.LastAnalysisStats),
			TimesSubmitted:    virusData.Data.Attributes.TimesSubmitted,
			TotalVotes:        convertMap(virusData.Data.Attributes.TotalVotes),
		}
		_, err := db.DB.NewInsert().Model(&virusRecord).Exec(context.Background())
		if err != nil {
			fmt.Println("Error insert virus record:", err)
		}
	}
	return nil
}
