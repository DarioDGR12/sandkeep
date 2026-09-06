package api

import (
	"fmt"
	"strings"
	"unicode"
)

func validateExecute(req *ExecuteRequest) error {
	req.Code = strings.TrimRight(req.Code, "\x00")
	req.Runtime = strings.ToLower(strings.TrimSpace(req.Runtime))
	req.SessionID = strings.TrimSpace(req.SessionID)

	if strings.TrimSpace(req.Code) == "" {
		return fmt.Errorf("code is required")
	}
	if len(req.Code) > MaxCodeBytes {
		return fmt.Errorf("code exceeds %d bytes", MaxCodeBytes)
	}
	if req.Runtime == "" {
		return fmt.Errorf("runtime is required")
	}
	if req.Runtime == "python3" {
		req.Runtime = "python"
	}
	switch req.Runtime {
	case "python", "node":
	default:
		return fmt.Errorf("runtime %q is not supported (want python or node)", req.Runtime)
	}
	if req.Timeout == 0 {
		req.Timeout = DefaultTimeoutS
	}
	if req.Timeout < 1 || req.Timeout > MaxTimeoutS {
		return fmt.Errorf("timeout must be between 1 and %d seconds", MaxTimeoutS)
	}
	if err := validateSessionID(req.SessionID); err != nil {
		return err
	}
	return nil
}

func validateSessionID(id string) error {
	if id == "" {
		return nil
	}
	if len(id) > MaxSessionIDLen {
		return fmt.Errorf("session_id exceeds %d characters", MaxSessionIDLen)
	}
	for _, r := range id {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("session_id may only contain letters, digits, '-' and '_'")
	}
	return nil
}
