package main

type SecurityInfo struct {
	SecurityEnabled bool   `json:"security_enabled"`
	WorkingDir      string `json:"working_dir,omitempty"`
	RunAsUser       string `json:"run_as_user,omitempty"`
	TimeoutApplied  bool   `json:"timeout_applied"`
}
