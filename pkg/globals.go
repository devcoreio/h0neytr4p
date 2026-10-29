package h0neytr4p

import (
	"os"
	"sync"
)

type Trap struct {
	Basicinfo BasicInfo   `json:"BasicInfo"`
	Behaviour []Behaviour `json:"Behaviour"`
}

type BasicInfo struct {
	Name            string `json:"Name"`
	Port            string `json:"Port"`
	Protocol        string `json:"Protocol"`
	Mitreattacktags string `json:"MitreAttackTags"`
	RiskRating      string `json:"RiskRating"`
	References      string `json:"References"`
	Description     string `json:"Description"`
}

type Behaviour struct {
	Request  Request  `json:"Request"`
	Response Response `json:"Response"`
	Trap     string   `json:"trap,omitempty"`
}

type Request struct {
	URL            string                 `json:"Url"`
	Method         string                 `json:"Method"`
	Proto          string                 `json:"Proto,omitempty"`
	Headers        map[string]interface{} `json:"Headers"`
	Params         map[string]interface{} `json:"Params"`
	HeaderContains map[string][]string    `json:"HeaderContains"`
}

type Response struct {
	Statuscode int                    `json:"StatusCode"`
	Body       string                 `json:"Body"`
	Headers    map[string]interface{} `json:"Headers"`
	Type       string                 `json:"Type"`
}

const (
	// Body caps mirror PHP's post_max_size (8M) so exploit-sized bodies are
	// captured; larger bodies get PHP's empty-superglobals behaviour, not a 413.
	MaxMultipartSize = 8 * 1024 * 1024
	MaxJSONFormSize  = 8 * 1024 * 1024

	// MaxStoredPayload bounds the raw body prefix kept in the log entry so an
	// oversized body cannot bloat Elasticsearch or process memory.
	MaxStoredPayload = 64 * 1024

	// T-Pot expects group-readable/group-writable runtime artifacts.
	RuntimeDirMode  os.FileMode = 0775
	RuntimeFileMode os.FileMode = 0775
)

var (
	logFile       *os.File
	logFileMutex  sync.Mutex
	payloadFolder string
	Verbose       bool
)
