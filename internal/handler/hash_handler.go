package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/datastore"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/db"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/model"
	"github.com/gin-gonic/gin"
)

const (
	DATE_PATTERN = "2006-01-02"
	MD5_FILE     = "md5"
	SHA1_FILE    = "sha1"
	SHA256_FILE  = "sha256"
)

//	func DeleteById(c *gin.Context) {
//		id := c.Param("id")
//		intId, err := strconv.Atoi(id)
//		if err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Not validated id"})
//			return
//		}
//		err = datastore.DeleteHashById(intId, c)
//		if err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Not found record with id " + id})
//			return
//		}
//		c.JSON(http.StatusOK, gin.H{"message": "Delete successfully"})
//	}
func SearchSuspectVirusHashByHash(c *gin.Context) {
	hash := c.Param("hash")
	var record model.VirusHash
	err := datastore.GetVirusHashByHash(&record, hash, c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not found record with hash " + hash})
		return
	}
	c.JSON(http.StatusOK, record)
}
func SearchRecordByDate(c *gin.Context) {
	dateString := c.Param("date")
	date, err := time.Parse(DATE_PATTERN, dateString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format to search"})
		return
	}
	var record model.Example
	err = datastore.GetHashByDate(date, &record, c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No records found with date " + dateString})
		return
	}
	c.JSON(http.StatusOK, record)
}

func DeleteRecordByDate(c *gin.Context) {
	dateString := c.Param("date")
	date, err := time.Parse(DATE_PATTERN, dateString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format"})
		return
	}
	_, err = db.DB.NewUpdate().Model((*model.Example)(nil)).Where("date::date = ?", date.Format(DATE_PATTERN)).Set("is_delete = true").Exec(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not found record with date " + dateString})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Record deleted successfully"})
}
func ConvertMap(in map[string]interface{}) map[string]int {
	out := make(map[string]int)
	for k, v := range in {
		if f, ok := v.(float64); ok {
			out[k] = int(f)
		}
	}
	return out
}

func ParseHashByDateCategory(c *gin.Context) {
	dateString := c.Param("date")
	category := c.Param("category")
	if category != MD5_FILE && category != SHA1_FILE && category != SHA256_FILE {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid category"})
		return
	}
	date, err := time.Parse(DATE_PATTERN, dateString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format"})
		return
	}
	var record model.Example
	datastore.GetHashByDate(date, &record, c)
	switch category {
	case MD5_FILE:
		md5 := record.Md5
		array := strings.Split(md5, "\n")
		if err := ProcessVirusData("md5", date, array, c); err != nil {
			fmt.Println(err)
			break
		}
	case SHA1_FILE:
		sha1 := record.Sha1
		array := strings.Split(sha1, "\n")
		if err := ProcessVirusData("sha1", date, array, c); err != nil {
			fmt.Println(err)
			break
		}
	case SHA256_FILE:
		sha256 := record.Sha256
		array := strings.Split(sha256, "\n")
		if err := ProcessVirusData("sha256", date, array, c); err != nil {
			fmt.Println(err)
			break
		}
	}
	var records []model.VirusHash
	err = datastore.GetVirusHashByDateAndCategory(&records, date, category, c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not found record" + dateString})
		return
	}
	c.JSON(http.StatusOK, records)
}

func ProcessVirusData(category string, date time.Time, array []string, c *gin.Context) error {
	for i := 0; i < len(array); i++ {
		virusData, errParse := ParseDataWithVirusTotal(array[i])
		if errParse != nil {
			fmt.Println(errParse)
			return errParse
		}
		errorInsert := InsertVirusData(virusData, array[i], date, category, c)
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

func InsertVirusData(virusData model.VirusApiResponse, hash string, date time.Time, hashKind string, c *gin.Context) error {
	malValue1, _ := virusData.Data.Attributes.LastAnalysisStats["malicious"].(float64)
	malValue2, _ := virusData.Data.Attributes.TotalVotes["malicious"].(float64)
	if malValue1 >= 1 || malValue2 >= 1 {
		virusRecord := model.VirusHash{
			Hash:              hash,
			HashKind:          hashKind,
			Date:              date,
			LastAnalysisStats: ConvertMap(virusData.Data.Attributes.LastAnalysisStats),
			TimesSubmitted:    virusData.Data.Attributes.TimesSubmitted,
			TotalVotes:        ConvertMap(virusData.Data.Attributes.TotalVotes),
		}
		err := datastore.InsertVirusData(&virusRecord, c)
		if err != nil {
			fmt.Println("Error insert virus record:", err)
		}
	}
	return nil
}
