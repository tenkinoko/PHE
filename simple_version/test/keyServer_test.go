package phe

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	ks "simple_phe/key_server"
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
	ks.RunKeyServer()
}
//func TestWorkFlow(t *testing.T){
//	// Initialization
//	res0, _ := GenerateServerKey()
//	res1, _ := Negotiation(res0)
//	SystemInitialization(res1)
//	// Enrollment
//	ClientInfo()
//	res2, _ := EncryptionA()
//	res3, _ := ThirdPartGeneration(res2)
//	EncryptionB(res3)
//	// Decryption
//	res4, _ := Decryption(Pw)
//	res5, _ := ZKProof(res4)
//	fmt.Println(Verifier(res5))
//}
//
//func TestWorkFlow_InvalidPassword(t *testing.T){
//	// Initialization
//	res0, _ := GenerateServerKey()
//	res1, _ := Negotiation(res0)
//	SystemInitialization(res1)
//	// Enrollment
//	ClientInfo()
//	res2, _ := EncryptionA()
//	res3, _ := ThirdPartGeneration(res2)
//	EncryptionB(res3)
//	// Decryption
//	pwInvalid := RandomZ().Bytes()
//	res4, _ := Decryption(pwInvalid)
//	res5, _ := ZKProof(res4)
//	fmt.Println(Verifier(res5))
//}
//
//
//func BenchmarkWorkFlow(b *testing.B) {
//	MockRandom()
//	b.ReportAllocs()
//	for i := 0; i < b.N; i++ {
//		MockRandom()
//		// Initialization
//		res0, _ := GenerateServerKey()
//		res1, _ := Negotiation(res0)
//		SystemInitialization(res1)
//		// Enrollment
//		ClientInfo()
//		res2, _ := EncryptionA()
//		res3, _ := ThirdPartGeneration(res2)
//		EncryptionB(res3)
//		// Decryption
//		res4, _ := Decryption(Pw)
//		res5, _ := ZKProof(res4)
//		Verifier(res5)
//	}
//}