package phe

import (
	"fmt"
	"testing"
)

func TestEnrolling(t *testing.T){
	enrolling()
}

func TestEncryption(t *testing.T){
	encryption()
}

func TestDecryption(t *testing.T){
	fmt.Println(decryption(pw))
}

func Test_proofOfSuccess(t *testing.T){
	fmt.Println(proofOfSuccess())
}

func BenchmarkEnrolling(b *testing.B){
	MockRandom()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		MockRandom()
		enrolling()
	}
}

func BenchmarkEncryption(b *testing.B){
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		encryption()
	}
}

func BenchmarkDecryption(b *testing.B){
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		decryption(pw)
	}
}

func Benchmark_proofOfSuccess(b *testing.B){
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		proofOfSuccess()
	}
}