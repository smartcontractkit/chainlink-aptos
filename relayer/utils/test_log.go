package utils

import (
	"fmt"
	"os"
	"sync"
)

var (
	logMutex sync.Mutex // Mutex to protect concurrent writes to the log file
)

// appendLog works like fmt.Printf but appends to /tmp/loop
func AppendLog(format string, a ...interface{}) (n int, err error) {
	logMutex.Lock()
	defer logMutex.Unlock()

	// Open the file in append mode, create it if it doesn't exist
	f, err := os.OpenFile("/tmp/loop", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("failed to open log file: %v", err)
	}
	defer f.Close()

	// Format and write the message
	message := fmt.Sprintf(format, a...)
	return f.WriteString(message + "\n")
}
