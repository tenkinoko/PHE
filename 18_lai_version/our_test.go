package phe

import (
	"fmt"
	"math/big"
	"testing"
)
var(
	c0 *big.Int
	c1 *big.Int
	u *big.Int
	gx1r *Point
)
func TestInitialize(t *testing.T){
	initialize()
}

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
	proofOfSuccess()
}

func BenchmarkInitialize(b *testing.B){
	MockRandom()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		MockRandom()
		initialize()
	}
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
	MockRandom()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		MockRandom()
		c0, c1, u, gx1r = proofOfSuccess()
	}
}

func Benchmark_veriferOfSuccess(b *testing.B){
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		verifierOfSuccess(c0, c1, u, gx1r)
	}
}
