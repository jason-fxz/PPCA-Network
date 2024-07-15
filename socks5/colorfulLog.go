package socks5

import (
	"fmt"
	"log"
	"os"
	"runtime"
)

// ANSI color codes
const (
	logDebugColor   = "\033[1;36m[DEBUG]\033[0m "
	logInfoColor    = "\033[1;34m[INFO]\033[0m "
	logWarningColor = "\033[1;33m[WARN]\033[0m "
	logErrorColor   = "\033[1;31m[ERR]\033[0m "
	logFatalColor   = "\033[1;35m[FATAL]\033[0m "
)

// Logger wraps standard log functionalities with color coding
type Logger struct {
	// debug:5 info:4 warn:3 error:2 fatal:1 silent:0
	logLevel  byte
	debugMode bool
}

// SetLogLevel sets the log level of the logger,
// debug:5 info:4 warn:3 error:2 fatal:1 silent:0
func (l *Logger) SetLogLevel(level byte) {
	if level <= 5 {
		log.Print(logInfoColor, "Log level set to ", level)
		l.logLevel = level
	} else {
		l.Warn("Invalid log level, set to default level 4")
		l.logLevel = 4
	}
}

// SetDebugMode sets the debug mode of the logger
// if debug mode is set to true, debug messages will be printed
func (l *Logger) SetDebugMode(debug bool) {
	l.debugMode = debug
}

// Debug logs error messages in orange
func (l *Logger) Debug(v ...interface{}) {
	if l.logLevel < 5 {
		return
	}
	if l.debugMode {
		_, file, line, _ := runtime.Caller(1)
		log.Print(logDebugColor, fmt.Sprintf("in file %s:%d: ", file, line), fmt.Sprint(v...))
	} else {
		log.Print(logDebugColor, fmt.Sprint(v...))
	}
}

// Info logs informational messages in blue
func (l *Logger) Info(v ...interface{}) {
	if l.logLevel < 4 {
		return
	}
	if l.debugMode {
		_, file, line, _ := runtime.Caller(1)
		log.Print(logInfoColor, fmt.Sprintf("in file %s:%d: ", file, line), fmt.Sprint(v...))
	} else {
		log.Print(logInfoColor, fmt.Sprint(v...))
	}
}

// Warn logs warning messages in yellow
func (l *Logger) Warn(v ...interface{}) {
	if l.logLevel < 3 {
		return
	}
	if l.debugMode {
		_, file, line, _ := runtime.Caller(1)
		log.Print(logWarningColor, fmt.Sprintf("in file %s:%d: ", file, line), fmt.Sprint(v...))
	} else {
		log.Print(logWarningColor, fmt.Sprint(v...))
	}
}

// Error logs error messages in red
func (l *Logger) Error(v ...interface{}) {
	if l.logLevel < 2 {
		return
	}
	if l.debugMode {
		_, file, line, _ := runtime.Caller(1)
		log.Print(logErrorColor, fmt.Sprintf("in file %s:%d: ", file, line), fmt.Sprint(v...))
	} else {
		log.Print(logErrorColor, fmt.Sprint(v...))
	}
}

// Fatal logs fatal messages in purple and exits
func (l *Logger) Fatal(v ...interface{}) {
	if l.logLevel < 1 {
		os.Exit(1)
	}
	if l.debugMode {
		_, file, line, _ := runtime.Caller(1)
		log.Print(logFatalColor, fmt.Sprintf("in file %s:%d: ", file, line), fmt.Sprint(v...))
	} else {
		log.Print(logFatalColor, fmt.Sprint(v...))
	}
	os.Exit(1)
}

var Log = Logger{4, false}
