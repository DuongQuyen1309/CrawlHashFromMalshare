package model

import (
	"time"

	"github.com/uptrace/bun"
)

type Example struct {
	bun.BaseModel `bun:"table:example2s"`

	Id     int       `bun:"id,pk,autoincrement"`
	Date   time.Time `bun:"date", type:date`
	Md5    string    `bun:"md5"`
	Sha1   string    `bun:"sha1"`
	Sha256 string    `bun:"sha256"`
}

type VirusHash struct {
	bun.BaseModel `bun:"table:virus_hashes"`

	ID                int            `bun:"id,pk,autoincrement"`
	Date              time.Time      `bun:"date", type:date`
	Hash              string         `bun:"hash"`
	HashKind          string         `bun:"hash_kind"`
	LastAnalysisStats map[string]int `bun:"last_analysis_stats,type:jsonb"`
	TimesSubmitted    int            `bun:"times_submitted"`
	TotalVotes        map[string]int `bun:"total_votes,type:jsonb"`
}
type VirusApiResponse struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			LastAnalysisStats map[string]interface{} `json:"last_analysis_stats"`
			TimesSubmitted    int                    `json:"times_submitted"`
			TotalVotes        map[string]interface{} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}
