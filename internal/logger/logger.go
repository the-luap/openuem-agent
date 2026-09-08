package logger

import "os"

type OpenUEMLogger struct {
	LogFile *os.File
}

func (l *OpenUEMLogger) Close() {
	if l != nil && l.LogFile != nil {
		_ = l.LogFile.Close()
	}
}
