package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/db"
	"github.com/DuongQuyen1309/crawlhashfrommalshare/internal/model"
)

var (
	reForDate = regexp.MustCompile(`href="(\d{4}-\d{2}-\d{2})/"`)
	reForTxt  = regexp.MustCompile(`href="(malshare_fileList.\d{4}-\d{2}-\d{2}.all.txt)"`)
)

const (
	PATTERN     = "2006-01-02"
	MD5_FILE    = "md5.txt"
	SHA1_FILE   = "sha1.txt"
	SHA256_FILE = "sha256.txt"
)

func CrawlData(ctx context.Context) error {
	matches, errDates := GetDates(reForDate, "https://malshare.com/daily/")
	if errDates != nil {
		return errDates
	}
	count := make(chan bool, 100)
	var wg sync.WaitGroup
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		date := match[1]
		wg.Add(1)
		count <- true
		go func(d string) {
			defer wg.Done()
			defer func() { <-count }()
			if ProcessADate(d, ctx) != nil {
				fmt.Println("Failed to process date:", d)
				return
			}
		}(date)
	}
	wg.Wait()
	return nil
}

func ProcessADate(a string, ctx context.Context) error {
	parts := strings.Split(a, "-")
	dirPath := filepath.Join(parts[0], parts[1], parts[2])

	err := os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		fmt.Println("Failed to create directory:", err)
		return err
	}
	linkAllTxt, errCertainDate := FindTxtFileForDate(reForTxt, a)
	if errCertainDate != nil || len(linkAllTxt) < 2 {
		fmt.Println("Not process txt file", a)
		return err
	}
	fileName := linkAllTxt[1]
	txtFileContent, errTxtFile := GetTxtFileContent(a, fileName)
	if errTxtFile != nil {
		return err
	}
	lines := strings.Split(txtFileContent, "\n")
	var md5List, sha1List, sha256List []string
	ExtractHashesFromLines(lines, &md5List, &sha1List, &sha256List)
	WriteToFiles(dirPath, md5List, sha1List, sha256List)
	var md5Content, sha1Content, sha256Content string
	md5Content, sha1Content, sha256Content, errReadFile := ReadFiles(dirPath, md5Content, sha1Content, sha256Content)
	if errReadFile != nil {
		return errReadFile
	}
	parsedDate, err := time.Parse(PATTERN, a)
	if err != nil {
		return err
	}
	errInsertDB := InsertDB(ctx, parsedDate, md5Content, sha1Content, sha256Content)
	if errInsertDB != nil {
		return errInsertDB
	}
	return nil
}

func WriteToFiles(dirPath string, md5List []string, sha1List []string, sha256List []string) error {
	files := map[string][]string{
		MD5_FILE:    md5List,
		SHA1_FILE:   sha1List,
		SHA256_FILE: sha256List,
	}
	for fileName, content := range files {
		fullPath := filepath.Join(dirPath, fileName)
		if err := WriteToFile(fullPath, content); err != nil {
			fmt.Printf("Failed to write %s", fileName)
			return err
		}
	}
	return nil
}
func WriteToFile(filePath string, data []string) error {
	f, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Failed to create file txt for md5 sha1, sha256:", err)
		return err
	}
	defer f.Close()
	for _, data := range data {
		_, err := f.WriteString(data + "\n")
		if err != nil {
			fmt.Println("Failed to write file txt for md5 sha1, sha256:", err)
			return err
		}
	}
	return nil
}
func InsertDB(ctx context.Context, parsedDate time.Time, md5Content string, sha1Content string, sha256Content string) error {
	var allRecords []model.Example
	errRetrieveDB := db.DB.NewSelect().Model(&allRecords).Where("date = ?", parsedDate).Scan(ctx)
	if errRetrieveDB != nil || len(allRecords) == 0 {
		return errRetrieveDB
	}
	_, errInsertDB := db.DB.NewInsert().Model(&model.Example{
		Date:   parsedDate,
		Md5:    md5Content,
		Sha1:   sha1Content,
		Sha256: sha256Content,
	}).Exec(ctx)
	if errInsertDB != nil {
		return errInsertDB
	}
	return nil
}
func ReadFiles(dirPath string, md5Content string, sha1Content string, sha256Content string) (string, string, string, error) {
	Contents := map[string]string{
		MD5_FILE:    md5Content,
		SHA1_FILE:   sha1Content,
		SHA256_FILE: sha256Content,
	}
	for fileName, _ := range Contents {
		var err error
		Contents[fileName], err = ReadFile(dirPath, fileName)
		if err != nil {
			return "", "", "", err
		}
	}
	return Contents[MD5_FILE], Contents[SHA1_FILE], Contents[SHA256_FILE], nil
}
func ReadFile(dirPath string, file string) (string, error) {
	resp, err := os.ReadFile(filepath.Join(dirPath, file))
	if err != nil {
		fmt.Printf("Failed to read file %s", file)
		return "", err
	}
	return string(resp), nil
}

func GetDates(regexp *regexp.Regexp, path string) ([][]string, error) {
	datesContent, err := GetURLContent(path)
	if err != nil {
		return nil, err
	}
	matches := regexp.FindAllStringSubmatch(datesContent, -1)
	return matches, nil
}

func FindTxtFileForDate(regexp *regexp.Regexp, date string) ([]string, error) {
	dateUrl := fmt.Sprintf("https://malshare.com/daily/%s/", date)
	certainDateContent, err := GetURLContent(dateUrl)
	if err != nil {
		return nil, err
	}
	linkAllTxt := regexp.FindStringSubmatch(certainDateContent)
	return linkAllTxt, nil
}

func GetTxtFileContent(date string, fileName string) (string, error) {
	fileTxtUrl := fmt.Sprintf("https://malshare.com/daily/%s/%s", date, fileName)
	txtFileContent, errTxtFile := GetURLContent(fileTxtUrl)
	if errTxtFile != nil {
		return "", errTxtFile
	}
	return txtFileContent, nil
}

func ExtractHashesFromLines(lines []string, md5List *[]string, sha1List *[]string, sha256List *[]string) {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		*md5List = append(*md5List, fields[0])
		*sha1List = append(*sha1List, fields[1])
		*sha256List = append(*sha256List, fields[2])
	}
}

func GetURLContent(path string) (string, error) {
	resp, err := http.Get(path)
	if err != nil {
		fmt.Println("Failed to open daily:", err)
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read daily:", err)
		return "", err
	}
	return string(body), nil
}
