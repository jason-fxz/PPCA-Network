package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
)

// ANSI color codes
const (
    InfoColor    = "\033[1;34m[INFO]\033[0m "
    WarningColor = "\033[1;33m[WARN]\033[0m "
    ErrorColor   = "\033[1;31m[ERR]\033[0m "
    FatalColor   = "\033[1;35[FATAL]\033[0m "
    DebugColor   = "\033[1;36m[DEBUG]\033[0m "
)

// Logger wraps standard log functionalities with color coding
type Logger struct{}

// Info logs informational messages in blue
func (l *Logger) Info(v ...interface{}) {
    log.Print(InfoColor, fmt.Sprint(v...))
}

// Warn logs warning messages in yellow
func (l *Logger) Warn(v ...interface{}) {
    log.Print(WarningColor, fmt.Sprint(v...))
}

// Error logs error messages in red
func (l *Logger) Error(v ...interface{}) {
    _, file, line, _ := runtime.Caller(1)
    log.Print(ErrorColor, fmt.Sprintf("in file %s:%d: ", file, line), fmt.Sprint(v...))
}

// Debug logs error messages in orange
func (l *Logger) Debug(v ...interface{}) {
    _, file, line, _ := runtime.Caller(1)
    log.Print(DebugColor, fmt.Sprintf("in file %s:%d: ", file, line), fmt.Sprint(v...))
}

// Fatal logs fatal messages in purple and exits
func (l *Logger) Fatal(v ...interface{}) {
    log.Print(FatalColor, fmt.Sprint(v...))
    os.Exit(1)
}


var Log = Logger{}
