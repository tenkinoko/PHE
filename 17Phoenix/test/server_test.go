package phe

import (
	s "18phe/server"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)
func GetAppPath() string {
	file, _ := exec.LookPath(os.Args[0])
	path, _ := filepath.Abs(file)
	index := strings.LastIndex(path, string(os.PathSeparator))
	return path[:index]
}

func TestKeyServerNetwork(t *testing.T) {
	log.Println(GetAppPath())
	s.RunServer()
}