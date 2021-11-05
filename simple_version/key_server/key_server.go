package key_server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"path"
	"runtime"

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
	//log.Printf("Received: %b", in.GetXs())
	xs := in.GetXs()
	xks := RandomZ()
	x_0 = HashZ(xs, xks.Bytes(), big.NewInt(0).Bytes())
	x_1 = HashZ(xs, xks.Bytes(), big.NewInt(1).Bytes())
	X_0 = new(Point).ScalarBaseMultInt(x_0)
	X_1 = new(Point).ScalarBaseMultInt(x_1)
	return &NegotiationResponse{X0: x_0.Bytes()}, nil
}

func (s *server)ThirdPartGeneration(ctx context.Context, in *T2Generation) (*T2Response, error) {
	//log.Printf("Received: %b", in.GetE1())
	Hpwn1_ := in.GetE1()
	gr, _ := PointUnmarshal(in.GetE2())
	k := in.GetE3()
	if x_1 == nil{
		x_1 = RandomZ()
	}
	T2e := Gf.AddBytes(k, new(big.Int).SetBytes(Hpwn1_))
	T2 := new(Point).ScalarBaseMultInt(T2e).Add(gr.ScalarMultInt(x_1))
	return &T2Response{T2: T2.Marshal()}, nil
}

func (s *server)ZKProof(ctx context.Context, in *ProofOfX) (*ProverResponse, error) {
	//log.Printf("Received: %b", in.GetFlag())
	T0, _ := PointUnmarshal(in.GetTT0())
	C0, _ := PointUnmarshal(in.GetFlag())
	T0x0 := T0.ScalarMultInt(x_0)
	hT0x0_ := HashZ(T0x0.Marshal())
	leftVal := T0x0.Add(new(Point).ScalarBaseMultInt(hT0x0_))
	if leftVal.Equal(C0) {
		return ProverOfSuccess(T0.Marshal())
	} else {
		return &ProverResponse{
			C0:   RandomZ().Bytes(),
			C1:   RandomZ().Bytes(),
			U:    RandomZ().Bytes(),
			GX1R: RandomZ().Bytes(),
			X1:   RandomZ().Bytes(),
		}, nil
	}
}

func ProverOfSuccess(t0 []byte) (*ProverResponse, error) {
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
	return &ProverResponse{
		C0:   c0.Bytes(),
		C1:   c1.Bytes(),
		U:    u.Bytes(),
		GX1R: gx1r.Marshal(),
		X1:   X_1.Marshal(),
	}, nil
}

func (s *server) Rotate(ctx context.Context, in* UpdateRequest) (*UpdateToken, error){
	gr_ := in.GetGr()
	gr, err := PointUnmarshal(gr_)
	if err != nil {
		return nil, errors.Wrap(err, "invalid gr")
	}
	a, b := RandomZ(), RandomZ()
	grx0 := gr.ScalarMultInt(x_0)
	grx1 := gr.ScalarMultInt(x_1)
	delta0Down := grx0.Add(new(Point).ScalarBaseMultInt(HashZ(grx0.Marshal()))).Neg()
	x_0 = new(big.Int).SetBytes(PadZ(Gf.Add(Gf.Mul(x_0, a), b).Bytes()))
	x_1 = new(big.Int).SetBytes(PadZ(Gf.Add(Gf.Mul(x_0, a), b).Bytes()))
	X_0 = new(Point).ScalarBaseMultInt(x_0)
	X_1 = new(Point).ScalarBaseMultInt(x_1)
	grx0_ := gr.ScalarMultInt(x_0)
	delta0 := grx0_.Add(new(Point).ScalarBaseMultInt(HashZ(grx0_.Marshal()))).Add(delta0Down)
	delta1 := gr.ScalarMultInt(x_1).Add(grx1.Neg())

	return &UpdateToken{
		Delta0: delta0.Marshal(),
		Delta1: delta1.Marshal(),
	}, nil
}

func RunKeyServer(){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(1)
	credpath := path.Join(path.Dir(filename), datafile)
	cert, err := tls.LoadX509KeyPair(credpath + "/server.crt", credpath + "/server.key")
	if err != nil {
		log.Fatalf("tls.LoadX509KeyPair err: %v", err)
	}

	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile(credpath + "/ca.crt")
	if err != nil {
		log.Fatalf("ioutil.ReadFile err: %v", err)
	}

	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("certPool.AppendCertsFromPEM err")
	}

	cred := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	})

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(cred))
	RegisterKeyPairGenServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}