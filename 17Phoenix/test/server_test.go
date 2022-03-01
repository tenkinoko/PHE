package phe

import (
	s "18phe/server"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"fmt"
	"runtime"
)
func GetAppPath() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))
	return path[:index]
}

func TestKeyServerNetwork(t *testing.T) {
	log.Println(GetAppPath())
	num := runtime.NumCPU()
	fmt.Println(num)
	s.RunServer()
}