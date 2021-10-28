/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package main implements a client for Greeter service.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"log"
	"math/big"
	"time"

	"google.golang.org/grpc"
	pb "sgx/sgx"
)

var (
	n = randomZ()
	zero = new(big.Int).SetInt64(0)
	one = new(big.Int).SetInt64(1)
	pw = []byte(pw_)
	ku = randomZ()
	ks = randomZ()
	H0 = hashZ(pw, n.Bytes(), zero.Bytes())
	H1 = hashZ(pw, n.Bytes(), one.Bytes())
	xs = randomZ()

	t0 []byte
	t1 []byte

)
const (
	address     = "localhost:50051"
	pw_ 		= "123456"
)

func hashZ(domain []byte, tuple ...[]byte) []byte {
	hash := sha1.New()
	/* #nosec */
	hash.Write(domain)
	for _, t := range tuple {
		/* #nosec */
		hash.Write(t)
	}
	return hash.Sum(nil)
}

func randomZ() *big.Int {
	RandReader := rand.Reader
	rz := makeZ(RandReader)
	return rz
}

func makeZ(reader io.Reader) *big.Int {
	buf := make([]byte, 32)
	n, err := reader.Read(buf)
	if err != nil || n != 32 {
		panic("random read failed")
	}
	return new(big.Int).SetBytes(buf)
}

// 填充数据
func padding(src []byte, blockSize int) []byte {
	padNum := blockSize - len(src) % blockSize
	pad := bytes.Repeat([]byte{byte(padNum)}, padNum)
	return append(src, pad...)
}

// 去掉填充数据
func unpadding(src []byte) []byte {
	n := len(src)
	unPadNum := int(src[n-1])
	return src[:n-unPadNum]
}

// 加密
func encryptAES(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = padding(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(src, src)
	return src, nil
}

// 解密
func decryptAES(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	blockMode.CryptBlocks(src, src)
	src = unpadding(src)
	return src, nil
}

func Encryption(resp *pb.NegoReply){
	hr0 := new(big.Int).SetBytes(resp.GetHr0())
	hr1 := new(big.Int).SetBytes(resp.GetHr1())
	h0 := new(big.Int).SetBytes(H0)
	h1 := new(big.Int).SetBytes(H1)
	h1ku := new(big.Int).Mul(h1, ku)
	t0_ := new(big.Int).Mul(h0, hr0)
	t1_ := new(big.Int).Mul(h1ku, hr1)
	t0, _ = encryptAES(t0_.Bytes(), ks.Bytes())
	t1, _ = encryptAES(t1_.Bytes(), ks.Bytes())
}

func Decryption(){
	
}

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPHEClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	r0, err0 := c.Negotiation(ctx, &pb.NegoRequest{Xs: xs.Bytes(), N: n.Bytes()})
	if err0 != nil {
		log.Fatalf("could not Negotiate: %v", err)
	}

	Encryption(r0)

}
