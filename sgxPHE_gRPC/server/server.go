package main

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	pb "sgx/sgx"
	"sgx/swu"

	"google.golang.org/grpc"
)

var (
	xks1 = randomZ()
	xks2 = randomZ()
	zero = new(big.Int).SetInt64(0)
	one  = new(big.Int).SetInt64(1)
	xk   *big.Int
	xv   *big.Int
	hr0  []byte
	hr1  []byte

	curve      = elliptic.P256()
	Gf     = swu.GF{P: curve.Params().N}
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
		X:   xk.Bytes(),
	}, nil

}

func (s *server) Decryption(ctx context.Context, in *pb.DecryptRequest) (*pb.DecryptReply, error) {
	c0_ := new(big.Int).SetBytes(in.GetC0())
	n_ := new(big.Int).SetBytes(in.GetN())
	tm := in.GetTm()
	if xk == nil {
		xk = randomZ()
	}
	rt := new(big.Int).SetBytes(hashZ(tm, xk.Bytes()))
	c0 := Gf.Div(c0_, rt)
	n := Gf.Div(n_, rt)
	hxn0 := new(big.Int).SetBytes(hashZ(xk.Bytes(), n.Bytes(), zero.Bytes()))
	fmt.Println(c0.Cmp(hxn0))
	if c0.Cmp(hxn0) == 0 {
		hr1_ := new(big.Int).Mul(new(big.Int).SetBytes(hr1), rt)
		return &pb.DecryptReply{Flag: "Success", Hr1_: hr1_.Bytes(), Tm: tm}, nil
	} else {
		hr1_ := []byte("000000")
		return &pb.DecryptReply{Flag: "Fail", Hr1_: hr1_, Tm: tm}, nil
	}
}

func (s *server) Update(ctx context.Context, in *pb.UpdateRequest) (*pb.UpdateReply, error) {
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
	delta0 := Gf.Mul(new(big.Int).SetBytes(hxkn0_), new(big.Int).SetBytes(hxkn0))
	delta1 := Gf.Mul(new(big.Int).SetBytes(hxkn1_), new(big.Int).SetBytes(hxkn1))
	return &pb.UpdateReply{
		Delta0: delta0.Bytes(),
		Delta1: delta1.Bytes(),
	}, nil
}

func hashZ(domain []byte, tuple ...[]byte) []byte {
	hash := sha256.New()
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
