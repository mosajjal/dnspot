package ui

import (
	"fmt"
)

func Infof(format string, val ...interface{}) {
	format = "[INFO] " + format
	UiLog.Write(fmt.Sprintf(format, val...) + "\n")
}
func Debugf(format string, val ...interface{}) {
	format = "[DBUG] " + format
	UiLog.Write(fmt.Sprintf(format, val...) + "\n")
}
func Warnf(format string, val ...interface{}) {
	format = "[WARN] " + format
	UiLog.Write(fmt.Sprintf(format, val...) + "\n")
}
func Errorf(format string, val ...interface{}) {
	format = "[ERRO] " + format
	UiLog.Write(fmt.Sprintf(format, val...) + "\n")
}
func Fatalf(format string, val ...interface{}) {
	format = "[FATA] " + format
	UiLog.Write(fmt.Sprintf(format, val...) + "\n")
}
