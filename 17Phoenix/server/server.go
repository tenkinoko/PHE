package server

import (
	. "18phe/phe"
	. "18phe/utils"
	"context"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"path"
	"runtime"
)
var (
	// Setup Phase
	s []byte
	x []byte
	y []byte
	ks []byte
	ns []byte
	h *Point
	z *Point

	// from client
	un []byte
	//c1 *Point
	//c2 *Point
	//c3 *Point

	// Enrollment Phase
	hs *Point

)

const (
	port = ":50051"
)

type server struct {
	UnimplementedPheWorkflowServer
}

func (s_ *server) Setup(ctx context.Context, in *SetupC) (*SetupS, error){
	s = RandomZ().Bytes()
	x = RandomZ().Bytes()
	y = RandomZ().Bytes()
	ks = RandomZ().Bytes()
	ns = RandomZ().Bytes()
	h = new(Point).ScalarBaseMult(s)
	z = new(Point).ScalarBaseMult(x).Add(h.ScalarMult(y))
	return &SetupS{
		H: h.Marshal(),
		Z: z.Marshal(),
	}, nil
}

func (s_ *server)Enrollment(ctx context.Context, in *EnrollmentC) (*EnrollmentS, error){
	un = in.GetUn()
	hs = new(Point).ScalarBaseMult(HashZ(un, ns).Bytes()).ScalarMult(ks)
	return &EnrollmentS{
		Hs: hs.Marshal(),
		Ns: ns,
	}, nil
}

func (s_ *server)Validation(ctx context.Context, in *ValidationC) (*ValidationS, error) {
	c1_, c2_, c3_ := in.GetC1(), in.GetC2(), in.GetC3()
	c1, _ := PointUnmarshal(c1_)
	c2, _ := PointUnmarshal(c2_)
	//c3, _ := PointUnmarshal(c3_)

	proof1 := c1.ScalarMult(s).Add(hs)
	mid := c2.Add(hs.Neg())
	proof2 := c1.ScalarMult(x).Add(mid.ScalarMult(y))

	c2V := new(big.Int).SetBytes(c2_)
	prf1V := new(big.Int).SetBytes(proof1.Marshal())
	c3V := new(big.Int).SetBytes(c3_)
	prf2V := new(big.Int).SetBytes(proof2.Marshal())
	flag1 := true
	if c2V.Cmp(prf1V) != 0 {
		flag1 = false
	}
	flag2 := true
	if c3V.Cmp(prf2V) != 0 {
		flag2 = false
	}
	return &ValidationS{Flag: flag1 && flag2}, nil
}

func RunServer(){
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
	s_ := grpc.NewServer(grpc.Creds(cred))
	RegisterPheWorkflowServer(s_, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s_.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}