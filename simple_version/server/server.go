package server

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"math/big"
	"path"
	"runtime"
	"time"

	. "simple_phe/utils"

	. "simple_phe/phe"
)

var (
	x0 *big.Int
	X0 *Point
	n  []byte
	r  []byte
	k  []byte
	Pw []byte

	T0 *Point
	T1 *Point
	T2 *Point
)

const (
	address 	= "localhost:50051"
)

func GenerateServerKey()[]byte{
	xs := RandomZ()
	return xs.Bytes()
}

// SystemInitialization Complete
func SystemInitialization(respBytes []byte){
	resp := &NegotiationResponse{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return
	}
	x0 = new(big.Int).SetBytes(resp.X0)
	X0 = new(Point).ScalarBaseMultInt(x0)
}

// TODO: whether a client is neccessary
func ClientInfo(){
	n = RandomZ().Bytes()
	r = RandomZ().Bytes()
	k = RandomZ().Bytes()
	Pw = RandomZ().Bytes()
}

func EncryptionA()([]byte, error){
	// T0 = g^r
	T0 = new(Point).ScalarBaseMult(r)
	// T1 = g^rx0 * g^H(g^rx0) * g^H(pw, n, 0)
	grx0 := X0.ScalarMult(r)
	Hgrx0 := sha1.Sum(grx0.Marshal())
	Hgrx0_ := Hgrx0[:]
	Hpwn0_ := HashPwd(Pw, n, 0)
	T1e := Gf.AddBytes(Hgrx0_, new(big.Int).SetBytes(Hpwn0_))
	T1 = grx0.Add(new(Point).ScalarBaseMultInt(T1e))

	Hpwn1_ := HashPwd(Pw, n, 1)
	return proto.Marshal(&T2Generation{
		E1: Hpwn1_,
		E2: r,
		E3: k,
	})
}

func EncryptionB(respBytes []byte){
	resp := &T2Response{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return
	}
	T2, _ = PointUnmarshal(resp.T2)
}

func Decryption(pw0 []byte)([]byte, error){
	// C0 = T1 / g^(H(pw0, n, 0))
	hpwn0 := HashPwd(pw0, n, 0)
	denominator := new(Point).ScalarBaseMult(hpwn0).Neg()
	C0 := T1.Add(denominator)
	T0x0 := T0.ScalarMultInt(x0)
	hT0x0 := sha1.Sum(T0x0.Marshal())
	hT0x0_ := hT0x0[:]

	// leftVal = T0^x0 * H(T0^x0)
	leftVal := T0x0.Add(new(Point).ScalarBaseMult(hT0x0_))
	var flag *big.Int
	if leftVal.Equal(C0) {
		flag = big.NewInt(1)
	} else {
		flag = big.NewInt(0)
	}
	return proto.Marshal(&ProofOfX{
		Flag: flag.Bytes(),
		TT0: T0.Marshal(),
	})
}

func Verifier(respBytes []byte) bool{
	if respBytes == nil{
		return false
	}
	resp := &ProverResponse{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		fmt.Println("Response Err at Verifier at server.go")
		return false
	}
	c0 := new(big.Int).SetBytes(resp.C0)
	c1 := new(big.Int).SetBytes(resp.C1)
	u := new(big.Int).SetBytes(resp.U)
	gx1r, _ := PointUnmarshal(resp.GX1R)
	gx1,_ := PointUnmarshal(resp.X1)

	cx0 := Gf.Mul(c0, x0)
	//cx1 := gf.Mul(c1, new(big.Int).SetBytes(x1))

	gx0r := X0.ScalarMult(r)

	t1e := Gf.Add(u, cx0)
	//t2e := gf.MulBytes(r, t1e)

	t1_ := gx1.ScalarMultInt(c1).Add(new(Point).ScalarBaseMultInt(t1e))
	t2_ := t1_.ScalarMult(r)

	c0_ := HashZ(X0.Marshal(), T0.Marshal(), gx0r.Marshal(), t1_.Marshal(), t2_.Marshal())
	c1_ := HashZ(gx1.Marshal(), T0.Marshal(), gx1r.Marshal(), t1_.Marshal(), t2_.Marshal())

	if c0.Cmp(c0_) != 0 {
		return false
	}
	if c1.Cmp(c1_) != 0 {
		return false
	}
	return true
}

func RunServer(){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(1)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath + "/client.crt", credpath + "/client.key")
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
		ServerName:   "localhost",
		RootCAs:      certPool,
	})

	// Set up a connection to the server.
	opts := []grpc.DialOption{
		// credentials.
		grpc.WithTransportCredentials(cred),
	}

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := NewKeyPairGenClient(conn)

	msg1 := GenerateServerKey()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.Negotiation(ctx, &NegotiationBegin{Xs: msg1})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %b", r.GetX0())
}










