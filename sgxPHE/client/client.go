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
	"fmt"
	"google.golang.org/grpc"
	"io"
	"log"
	"math/big"
	pb "sgx/sgx"
	"time"
)


var (
	n = randomZ()
	zero = new(big.Int).SetInt64(0)
	one = new(big.Int).SetInt64(1)
	pw = []byte(pw_)
	ku = randomZ()
	ks []byte
	H0 []byte
	H1 []byte
	xs = randomZ()

	t0 []byte
	t1 []byte


	x *big.Int

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
	nnn := len(src)
	unPadNum := int(src[nnn-1])
	return src[:nnn-unPadNum]
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
	H0 = hashZ(pw, n.Bytes(), zero.Bytes())
	H1 = hashZ(pw, n.Bytes(), one.Bytes())
	hr0 := new(big.Int).SetBytes(resp.GetHr0())
	hr1 := new(big.Int).SetBytes(resp.GetHr1())
	x = new(big.Int).SetBytes(resp.GetX())
	h0 := new(big.Int).SetBytes(H0)
	h1 := new(big.Int).SetBytes(H1)
	h1ku := new(big.Int).Mul(h1, ku)
	t0_ := new(big.Int).Mul(h0, hr0)
	t1_ := new(big.Int).Mul(h1ku, hr1)
	ctxt := make([]byte, aes.BlockSize+len(t0_.Bytes()))
	ks = ctxt[:aes.BlockSize]
	t0, _ = encryptAES(t0_.Bytes(), ks)
	t1, _ = encryptAES(t1_.Bytes(), ks)
}

func Validation(pw0 []byte)([]byte, []byte, []byte, []byte, []byte){
	h0_ := new(big.Int).SetBytes(hashZ(pw0, n.Bytes(), zero.Bytes()))
	t0_, _ := decryptAES(t0, ks)
	t1_, _ := decryptAES(t1, ks)
	c0 := new(big.Int).Div(new(big.Int).SetBytes(t0_), h0_)
	tm_ := time.Now().Format("2006-01-02 15:04:05")
	tm := []byte(tm_)
	rt := new(big.Int).SetBytes(hashZ(tm, x.Bytes()))
	c0_ := new(big.Int).Mul(c0, rt)
	n_ := new(big.Int).Mul(n, rt)
	return t0_, t1_, c0_.Bytes(), n_.Bytes(), tm
}

func Decryption(resp *pb.DecryptReply, t1_ []byte){
	hr1_ := resp.GetHr1_()
	tm := resp.GetTm()
	rt := new(big.Int).SetBytes(hashZ(tm, x.Bytes()))
	hr1 := new(big.Int).Div(new(big.Int).SetBytes(hr1_), rt)
	c1 := new(big.Int).Div(new(big.Int).SetBytes(t1_), hr1)
	ku_ := new(big.Int).Div(c1, new(big.Int).SetBytes(H1))
	if ku.Cmp(ku_) != 0 {
		fmt.Println("Fail After Success!")
	}

}

func UpdateRecord(resp *pb.UpdateReply, x_ *big.Int)([]byte, []byte){
	delta0 := resp.GetDelta0()
	delta1 := resp.GetDelta1()
	t0_, _ := decryptAES(t0, ks)
	t1_, _ := decryptAES(t1, ks)
	t0u_ := new(big.Int).Mul(new(big.Int).SetBytes(t0_), new(big.Int).SetBytes(delta0))
	t1u_ := new(big.Int).Mul(new(big.Int).SetBytes(t1_), new(big.Int).SetBytes(delta1))
	x = x_

	ctxt := make([]byte, aes.BlockSize+len(t0u_.Bytes()))
	ks_ := ctxt[:aes.BlockSize]
	t0u, _ := encryptAES(t0u_.Bytes(), ks_)
	t1u, _ := encryptAES(t1u_.Bytes(), ks_)
	return t0u, t1u
}

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewPHEClient(conn)
	t00 := time.Now()
	t11 := t00.Sub(t00)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*200)
	defer cancel()
	var timeNeg, timeEnc, timeVal, timeDec, timeClientDec, timeUpdate = t11, t11, t11, t11, t11, t11
	for i := 0; i < 10000; i++{
		t3 := time.Now()
		r0, err0 := c.Negotiation(ctx, &pb.NegoRequest{Xs: xs.Bytes(), N: n.Bytes()})
		if err0 != nil {
			log.Fatalf("could not Negotiate: %v", err)
		}
		t4 := time.Now()
		Encryption(r0)
		t5 := time.Now()

		t0_, t1_, c0_, n_, tm := Validation(pw)
		t6 := time.Now()
		r1, err1 := c.Decryption(ctx, &pb.DecryptRequest{
			C0: c0_,
			N:  n_,
			Tm: tm,
		})

		if err1 != nil {
			log.Fatalf("could not Decrypt: %v", err1)
		}
		t7 := time.Now()
		if r1.GetFlag() == "Success" {
			Decryption(r1, t1_)
		} else {
			fmt.Println("Fail!!")
		}
		t8 := time.Now()



		x_ := randomZ()
		r2, err2 := c.Update(ctx, &pb.UpdateRequest{N: n.Bytes(), Xs: x_.Bytes()})
		if err2 != nil {
			log.Fatalf("could not Update: %v", err)
		}
		for j := 0; j < 1; j++{
			t0Ex, _ := encryptAES(t0_, ks)
			t1Ex, _ := encryptAES(t1_, ks)
			UpdateRecord(r2, x_)
			t0 = t0Ex
			t1 = t1Ex
		}
		t9 := time.Now()

		timeNeg += t4.Sub(t3)
		timeEnc += t5.Sub(t4)
		timeVal += t6.Sub(t5)
		timeDec += t7.Sub(t6)
		timeClientDec += t8.Sub(t7)
		timeUpdate += t9.Sub(t8)
	}
	totalTime := timeNeg + timeEnc + timeVal + timeDec + timeClientDec
	fmt.Println(timeNeg/10000, timeEnc/10000, timeVal/10000, timeDec/10000, timeClientDec/10000, timeUpdate/10000, totalTime/10000)
}
