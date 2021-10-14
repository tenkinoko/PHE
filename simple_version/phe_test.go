package phe

import (
	"fmt"
	"testing"
)

func TestWorkFlow(t *testing.T){
	// Initialize
	res0, _ := GenerateServerKey()
	res1, _ := Negotiation(res0)
	SystemInitialization(res1)

	ClientInfo()
	res2, _ := EncryptionA()
	res3, _ := ThirdPartGeneration(res2)
	EncryptionB(res3)

	res4, _ := Decryption(pw)
	res5, _ := ZKProof(res4)
	fmt.Println(Verifier(res5))
}

