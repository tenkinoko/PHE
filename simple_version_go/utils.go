package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)
var (
	randReader = rand.Reader
	curve      = elliptic.P256()
	curveG     = new(Point).ScalarBaseMultInt(new(big.Int).SetUint64(1)).Marshal()
)


func main(){
	fmt.Println(curveG)
}