package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	numZero []byte
	numOne []byte

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
func SystemInitialization(xx0 []byte){
	x0 = new(big.Int).SetBytes(xx0)
	X0 = new(Point).ScalarBaseMultInt(x0)
}

// TODO: whether a client is neccessary
func ClientInfo(){
	n = RandomZ().Bytes()
	r = RandomZ().Bytes()
	k = RandomZ().Bytes()
	Pw = RandomZ().Bytes()
	numZero = big.NewInt(0).Bytes()
	numOne = big.NewInt(1).Bytes()
}

func EncryptionA()([]byte, []byte, []byte){
	// T0 = g^r
	T0 = new(Point).ScalarBaseMult(r)
	// T1 = g^rx0 * g^H(g^rx0) * g^H(pw, n, 0)
	grx0 := X0.ScalarMult(r)
	//Hgrx0 := sha1.Sum(grx0.Marshal())
	//Hgrx0_ := Hgrx0[:]
	Hgrx0_ := HashZ(grx0.Marshal())
	Hpwn0_ := HashZ(Pw, n, numZero)
	T1e := Gf.Add(Hgrx0_, new(big.Int).Set(Hpwn0_))
	T1 = grx0.Add(new(Point).ScalarBaseMultInt(T1e))

	Hpwn1_ := HashZ(Pw, n, numOne).Bytes()
	return Hpwn1_, r, k
}

func EncryptionB(TT2 []byte){
	T2, _ = PointUnmarshal(TT2)
}

func Decryption(pw0 []byte)([]byte, []byte){
	// C0 = T1 / g^(H(pw0, n, 0))
	hpwn0 := HashZ(pw0, n, numZero)
	denominator := new(Point).ScalarBaseMultInt(hpwn0).Neg()
	C0 := T1.Add(denominator)
	T0x0 := T0.ScalarMultInt(x0)
	//hT0x0 := sha1.Sum(T0x0.Marshal())
	//hT0x0_ := hT0x0[:]
	hT0x0_ := HashZ(T0x0.Marshal())

	// leftVal = T0^x0 * H(T0^x0)
	leftVal := T0x0.Add(new(Point).ScalarBaseMultInt(hT0x0_))
	var flag *big.Int
	if leftVal.Equal(C0) {
		flag = big.NewInt(1)
	} else {
		flag = big.NewInt(0)
	}
	return flag.Bytes(), T0.Marshal()
}

func Verifier(C0, C1, U, GX1R, X1 []byte) bool{
	c0 := new(big.Int).SetBytes(C0)
	c1 := new(big.Int).SetBytes(C1)
	u := new(big.Int).SetBytes(U)
	gx1r, _ := PointUnmarshal(GX1R)
	gx1,_ := PointUnmarshal(X1)

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

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ClientInfo()
	msg1 := GenerateServerKey()
	r, err := c.Negotiation(ctx, &NegotiationBegin{Xs: msg1})
	if err != nil {
		log.Fatalf("could not generate key pairs: %v", err)
	}
	log.Printf("KeyPairGen Finish")
	SystemInitialization(r.GetX0())

	msg2a, msg2b, msg2c := EncryptionA()
	r1, err1 := c.ThirdPartGeneration(ctx, &T2Generation{E1: msg2a, E2: msg2b, E3: msg2c})
	if err1 != nil {
		log.Fatalf("could not enroll: %v", err1)
	}
	log.Printf("Enrollment Finish")
	EncryptionB(r1.GetT2())

	msg3a, msg3b := Decryption(Pw)
	r2, err2 := c.ZKProof(ctx, &ProofOfX{Flag: msg3a, TT0:  msg3b})
	if err2 != nil {
		log.Fatalf("could not zero knowledge proof: %v", err2)
	}
	log.Printf("ZeroKnowledge Finish")

	rep3a, rep3b, rep3c, rep3d, rep3e := r2.GetC0(), r2.GetC1(), r2.GetU(), r2.GetGX1R(), r2.GetX1()
	fmt.Println(Verifier(rep3a, rep3b, rep3c, rep3d, rep3e))

	msg4 := T0.Marshal()
	r3, err3 := c.Rotate(ctx, &UpdateRequest{Gr: msg4})
	if err3 != nil {
		log.Fatalf("could not Rotate: %v", err2)
	}
	log.Printf("Rotate Finish")
	delta0, err4a := PointUnmarshal(r3.GetDelta0())
	delta1, err4b := PointUnmarshal(r3.GetDelta1())

	if err4a != nil {
		log.Fatalf("invalid deltas: %v", err4a)
	}

	if err4b != nil {
		log.Fatalf("invalid deltas: %v", err4b)
	}

	T0 = T0.Add(delta0)
	T1 = T1.Add(delta1)
}





