package key_server

import (
	"context"
	"log"
	"math/big"
	"net"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"

	. "simple_phe/utils"

	. "simple_phe/phe"
	//"math/big"
)

var (
	x_0 *big.Int
	x_1 *big.Int
	X_0 *Point
	X_1 *Point
)

const (
	port = ":50051"
)

type server struct {
	UnimplementedKeyPairGenServer
}

// Negotiation between Server and Key Server At the very beginning
func (s *server) Negotiation(ctx context.Context, in *NegotiationBegin) (*NegotiationResponse, error) {
	log.Printf("Received: %b", in.GetXs())
	xs := in.GetXs()
	xks := RandomZ()
	x_0 = HashZ(xs, xks.Bytes(), big.NewInt(0).Bytes())
	x_1 = HashZ(xs, xks.Bytes(), big.NewInt(1).Bytes())
	X_0 = new(Point).ScalarBaseMultInt(x_0)
	X_1 = new(Point).ScalarBaseMultInt(x_1)
	return &NegotiationResponse{X0: x_0.Bytes()}, nil
}

func ThirdPartGeneration(respBytes []byte) ([]byte, error) {
	resp := &T2Generation{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return nil, err
	}
	Hpwn1_ := resp.E1
	r := resp.E2
	k := resp.E3
	T2e := Gf.Add(Gf.MulBytes(r, x_1), Gf.AddBytes(k, new(big.Int).SetBytes(Hpwn1_)))
	T2 := new(Point).ScalarBaseMultInt(T2e)
	return proto.Marshal(&T2Response{
		T2: T2.Marshal(),
	})
}

func ZKProof(respBytes []byte) ([]byte, error) {
	resp := &ProofOfX{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return nil, err
	}
	T0 := resp.TT0
	FlagMsg := resp.Flag
	Flag := new(big.Int).SetBytes(FlagMsg)
	if Flag.Cmp(big.NewInt(1)) == 0 {
		return ProverOfSuccess(T0)

	} else {
		return nil, nil
	}

}

func ProverOfSuccess(t0 []byte) ([]byte, error) {
	gr, _ := PointUnmarshal(t0)
	v := RandomZ().Bytes()
	t1 := new(Point).ScalarBaseMult(v)
	t2 := gr.ScalarMult(v)

	gx0r := gr.ScalarMultInt(x_0)
	gx1r := gr.ScalarMultInt(x_1)

	c0 := HashZ(X_0.Marshal(), gr.Marshal(), gx0r.Marshal(), t1.Marshal(), t2.Marshal())
	c1 := HashZ(X_1.Marshal(), gr.Marshal(), gx1r.Marshal(), t1.Marshal(), t2.Marshal())

	cx0 := Gf.Mul(c0, x_0)
	cx1 := Gf.Mul(c1, x_1)

	cx0neg := Gf.Neg(cx0)
	cx1neg := Gf.Neg(cx1)

	u := Gf.AddBytes(v, Gf.Add(cx0neg, cx1neg))

	// + gx1r -> server
	return proto.Marshal(&ProverResponse{
		C0:   c0.Bytes(),
		C1:   c1.Bytes(),
		U:    u.Bytes(),
		GX1R: gx1r.Marshal(),
		X1:   X_1.Marshal(),
	})
}

func RunKeyServer(){
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterKeyPairGenServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}