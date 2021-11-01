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

// Package main implements a server for Greeter service.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"google.golang.org/grpc"
	"io"
	"log"
	"math/big"
	"net"
	pb "sgx/sgx"
)

var (
	xks1 = randomZ()
	xks2 = randomZ()
	zero = new(big.Int).SetInt64(0)
	one = new(big.Int).SetInt64(1)
	xk *big.Int
	xv *big.Int
	hr0 []byte
	hr1 []byte
)
const (
	port = ":50051"
)

type server struct {
	pb.UnimplementedPHEServer
}

func (s *server) Negotiation(ctx context.Context, in *pb.NegoRequest) (*pb.NegoReply, error) {
	xs := in.GetXs()
	n := in.GetN()
	xk = new(big.Int).SetBytes(hashZ(xs, xks1.Bytes(), zero.Bytes()))
	xv = new(big.Int).SetBytes(hashZ(xs, xks2.Bytes(), zero.Bytes()))
	hr0 = hashZ(xk.Bytes(), n, zero.Bytes())
	hr1 = hashZ(xk.Bytes(), n, one.Bytes())
	return &pb.NegoReply{
		Hr0: hr0,
		Hr1: hr1,
		X: xk.Bytes(),
	}, nil

}

func (s *server) Decryption(ctx context.Context, in *pb.DecryptRequest) (*pb.DecryptReply, error) {
	c0_ := new(big.Int).SetBytes(in.GetC0())
	n_ := new(big.Int).SetBytes(in.GetN())
	tm := in.GetTm()
	rt := new(big.Int).SetBytes(hashZ(tm, xk.Bytes()))
	c0 := new(big.Int).Div(c0_, rt)
	n := new(big.Int).Div(n_, rt)
	hxn0 := new(big.Int).SetBytes(hashZ(xk.Bytes(), n.Bytes(), zero.Bytes()))
	if c0.Cmp(hxn0) == 0 {
		hr1_ := new(big.Int).Mul(new(big.Int).SetBytes(hr1), rt)
		return &pb.DecryptReply{Flag: "Success", Hr1_: hr1_.Bytes(), Tm: tm}, nil
	} else {
		hr1_ := []byte("000000")
		return &pb.DecryptReply{Flag: "Fail", Hr1_: hr1_, Tm: tm}, nil
	}
}

func (s *server) Update(ctx context.Context, in *pb.UpdateRequest) (*pb.UpdateReply, error){
	n := in.GetN()
	xs := in.GetXs()
	xks1 = randomZ()
	xks2 = randomZ()
	xk_ := new(big.Int).SetBytes(hashZ(xs, xks1.Bytes(), zero.Bytes()))
	xv_ := new(big.Int).SetBytes(hashZ(xs, xks2.Bytes(), zero.Bytes()))
	xv = xv_
	hxkn0 := hashZ(xk.Bytes(), n, zero.Bytes())
	hxkn1 := hashZ(xk.Bytes(), n, one.Bytes())
	hxkn0_ := hashZ(xk_.Bytes(), n, zero.Bytes())
	hxkn1_ := hashZ(xk_.Bytes(), n, one.Bytes())
	delta0 := new(big.Int).Mul(new(big.Int).SetBytes(hxkn0_), new(big.Int).SetBytes(hxkn0))
	delta1 := new(big.Int).Mul(new(big.Int).SetBytes(hxkn1_), new(big.Int).SetBytes(hxkn1))
	return &pb.UpdateReply{
		Delta0: delta0.Bytes(),
		Delta1: delta1.Bytes(),
	}, nil
}



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


func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterPHEServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
