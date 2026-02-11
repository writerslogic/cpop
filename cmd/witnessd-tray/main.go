package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "witnessd-tray is only supported on Windows.")
		os.Exit(1)
	}
	runTray()
}
