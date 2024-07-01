package main

import (
	"fmt"
	"log"
	"os"
)

// ANSI color codes
const (
    InfoColor    = "\033[1;34m[INFO]\033[0m %s"
    WarningColor = "\033[1;33m[WARN]\033[0m %s"
    ErrorColor   = "\033[1;31m[ERR]\033[0m %s"
    FatalColor   = "\033[1;35[FATAL]\033[0m %s"
    DebugColor   = "\033[1;36m[DEBUG]\033[0m %s"
)

// Logger wraps standard log functionalities with color coding
type Logger struct{}

// Info logs informational messages in blue
func (l *Logger) Info(v ...interface{}) {
    log.Printf(InfoColor, fmt.Sprint(v...))
}

// Warn logs warning messages in yellow
func (l *Logger) Warn(v ...interface{}) {
    log.Printf(WarningColor, fmt.Sprint(v...))
}

// Error logs error messages in red
func (l *Logger) Error(v ...interface{}) {
    log.Printf(ErrorColor, fmt.Sprint(v...))
}

// Debug logs error messages in orange
func (l *Logger) Debug(v ...interface{}) {
    log.Printf(DebugColor, fmt.Sprint(v...))
}

// Fatal logs fatal messages in purple and exits
func (l *Logger) Fatal(v ...interface{}) {
    log.Printf(FatalColor, fmt.Sprint(v...))
    os.Exit(1)
}


var Log = Logger{}
