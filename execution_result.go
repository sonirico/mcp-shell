package main

import "time"

type ExecutionResult struct {
	Status        string        `json:"status"`
	ExitCode      int           `json:"exit_code"`
	Stdout        string        `json:"stdout"`
	Stderr        string        `json:"stderr"`
	Command       string        `json:"command"`
	ExecutionTime time.Duration `json:"execution_time"`
	SecurityInfo  *SecurityInfo `json:"security_info,omitempty"`
}
