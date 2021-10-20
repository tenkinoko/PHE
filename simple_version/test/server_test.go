package phe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"path"
	"runtime"
	"testing"
	"time"

	. "simple_phe/phe"
	. "simple_phe/server"
	. "simple_phe/utils"
)

const (
	address 	= "localhost:50051"
)

func Test_Workflow(t *testing.T){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
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

	T2 = T2.Add(delta1)
	T1 = T1.Add(delta0)
}

func Benchmark_Workflow(b *testing.B){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
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

	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		ClientInfo()
		msg1 := GenerateServerKey()
		r, err := c.Negotiation(ctx, &NegotiationBegin{Xs: msg1})
		if err != nil {
			log.Fatalf("could not generate key pairs: %v", err)
		}
		//log.Printf("KeyPairGen Finish")
		SystemInitialization(r.GetX0())

		msg2a, msg2b, msg2c := EncryptionA()
		r1, err1 := c.ThirdPartGeneration(ctx, &T2Generation{E1: msg2a, E2: msg2b, E3: msg2c})
		if err1 != nil {
			log.Fatalf("could not enroll: %v", err1)
		}
		//log.Printf("Enrollment Finish")
		EncryptionB(r1.GetT2())

		msg3a, msg3b := Decryption(Pw)
		r2, err2 := c.ZKProof(ctx, &ProofOfX{Flag: msg3a, TT0: msg3b})
		if err2 != nil {
			log.Fatalf("could not zero knowledge proof: %v", err2)
		}
		//log.Printf("ZeroKnowledge Finish")

		rep3a, rep3b, rep3c, rep3d, rep3e := r2.GetC0(), r2.GetC1(), r2.GetU(), r2.GetGX1R(), r2.GetX1()
		Verifier(rep3a, rep3b, rep3c, rep3d, rep3e)

		msg4 := T0.Marshal()
		r3, err3 := c.Rotate(ctx, &UpdateRequest{Gr: msg4})
		if err3 != nil {
			log.Fatalf("could not Rotate: %v", err3)
		}
		//log.Printf("Rotate Finish")
		delta0, err4a := PointUnmarshal(r3.GetDelta0())
		delta1, err4b := PointUnmarshal(r3.GetDelta1())

		if err4a != nil {
			log.Fatalf("invalid deltas: %v", err4a)
		}

		if err4b != nil {
			log.Fatalf("invalid deltas: %v", err4b)
		}

		T2 = T2.Add(delta1)
		T1 = T1.Add(delta0)
	}
}

func Benchmark_Negotiation(b *testing.B){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
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

	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		ClientInfo()
		msg1 := GenerateServerKey()
		r, err := c.Negotiation(ctx, &NegotiationBegin{Xs: msg1})
		if err != nil {
			log.Fatalf("could not generate key pairs: %v", err)
		}
		//log.Printf("KeyPairGen Finish")
		SystemInitialization(r.GetX0())
	}
	MockRandom()
	msg2a, msg2b, msg2c := EncryptionA()
	r1, err1 := c.ThirdPartGeneration(ctx, &T2Generation{E1: msg2a, E2: msg2b, E3: msg2c})
	if err1 != nil {
		log.Fatalf("could not enroll: %v", err1)
	}
	//log.Printf("Enrollment Finish")
	EncryptionB(r1.GetT2())

	msg3a, msg3b := Decryption(Pw)
	r2, err2 := c.ZKProof(ctx, &ProofOfX{Flag: msg3a, TT0: msg3b})
	if err2 != nil {
		log.Fatalf("could not zero knowledge proof: %v", err2)
	}
	//log.Printf("ZeroKnowledge Finish")

	rep3a, rep3b, rep3c, rep3d, rep3e := r2.GetC0(), r2.GetC1(), r2.GetU(), r2.GetGX1R(), r2.GetX1()
	Verifier(rep3a, rep3b, rep3c, rep3d, rep3e)

	msg4 := T0.Marshal()
	r3, err3 := c.Rotate(ctx, &UpdateRequest{Gr: msg4})
	if err3 != nil {
		log.Fatalf("could not Rotate: %v", err3)
	}
	//log.Printf("Rotate Finish")
	delta0, err4a := PointUnmarshal(r3.GetDelta0())
	delta1, err4b := PointUnmarshal(r3.GetDelta1())

	if err4a != nil {
		log.Fatalf("invalid deltas: %v", err4a)
	}

	if err4b != nil {
		log.Fatalf("invalid deltas: %v", err4b)
	}

	T2 = T2.Add(delta1)
	T1 = T1.Add(delta0)

}

func Benchmark_Encryption(b *testing.B){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
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

	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	MockRandom()
	ClientInfo()
	msg1 := GenerateServerKey()
	r, err := c.Negotiation(ctx, &NegotiationBegin{Xs: msg1})
	if err != nil {
		log.Fatalf("could not generate key pairs: %v", err)
	}
	//log.Printf("KeyPairGen Finish")
	SystemInitialization(r.GetX0())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg2a, msg2b, msg2c := EncryptionA()
		r1, err1 := c.ThirdPartGeneration(ctx, &T2Generation{E1: msg2a, E2: msg2b, E3: msg2c})
		if err1 != nil {
			log.Fatalf("could not enroll: %v", err1)
		}
		//log.Printf("Enrollment Finish")
		EncryptionB(r1.GetT2())
	}

	msg3a, msg3b := Decryption(Pw)
	r2, err2 := c.ZKProof(ctx, &ProofOfX{Flag: msg3a, TT0: msg3b})
	if err2 != nil {
		log.Fatalf("could not zero knowledge proof: %v", err2)
	}
	//log.Printf("ZeroKnowledge Finish")

	rep3a, rep3b, rep3c, rep3d, rep3e := r2.GetC0(), r2.GetC1(), r2.GetU(), r2.GetGX1R(), r2.GetX1()
	Verifier(rep3a, rep3b, rep3c, rep3d, rep3e)

	msg4 := T0.Marshal()
	r3, err3 := c.Rotate(ctx, &UpdateRequest{Gr: msg4})
	if err3 != nil {
		log.Fatalf("could not Rotate: %v", err3)
	}
	//log.Printf("Rotate Finish")
	delta0, err4a := PointUnmarshal(r3.GetDelta0())
	delta1, err4b := PointUnmarshal(r3.GetDelta1())

	if err4a != nil {
		log.Fatalf("invalid deltas: %v", err4a)
	}

	if err4b != nil {
		log.Fatalf("invalid deltas: %v", err4b)
	}

	T2 = T2.Add(delta1)
	T1 = T1.Add(delta0)
}

func Benchmark_Decryption(b *testing.B){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
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

	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	MockRandom()
	ClientInfo()
	msg1 := GenerateServerKey()
	r, err := c.Negotiation(ctx, &NegotiationBegin{Xs: msg1})
	if err != nil {
		log.Fatalf("could not generate key pairs: %v", err)
	}
	//log.Printf("KeyPairGen Finish")
	SystemInitialization(r.GetX0())

	MockRandom()
	msg2a, msg2b, msg2c := EncryptionA()
	r1, err1 := c.ThirdPartGeneration(ctx, &T2Generation{E1: msg2a, E2: msg2b, E3: msg2c})
	if err1 != nil {
		log.Fatalf("could not enroll: %v", err1)
	}
	//log.Printf("Enrollment Finish")
	EncryptionB(r1.GetT2())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg3a, msg3b := Decryption(Pw)
		r2, err2 := c.ZKProof(ctx, &ProofOfX{Flag: msg3a, TT0: msg3b})
		if err2 != nil {
			log.Fatalf("could not zero knowledge proof: %v", err2)
		}
		//log.Printf("ZeroKnowledge Finish")

		rep3a, rep3b, rep3c, rep3d, rep3e := r2.GetC0(), r2.GetC1(), r2.GetU(), r2.GetGX1R(), r2.GetX1()
		Verifier(rep3a, rep3b, rep3c, rep3d, rep3e)
	}

	msg4 := T0.Marshal()
	r3, err3 := c.Rotate(ctx, &UpdateRequest{Gr: msg4})
	if err3 != nil {
		log.Fatalf("could not Rotate: %v", err3)
	}
	//log.Printf("Rotate Finish")
	delta0, err4a := PointUnmarshal(r3.GetDelta0())
	delta1, err4b := PointUnmarshal(r3.GetDelta1())

	if err4a != nil {
		log.Fatalf("invalid deltas: %v", err4a)
	}

	if err4b != nil {
		log.Fatalf("invalid deltas: %v", err4b)
	}

	T2 = T2.Add(delta1)
	T1 = T1.Add(delta0)
}

func Benchmark_Update(b *testing.B){
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
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

	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	MockRandom()
	ClientInfo()
	msg1 := GenerateServerKey()
	r, err := c.Negotiation(ctx, &NegotiationBegin{Xs: msg1})
	if err != nil {
		log.Fatalf("could not generate key pairs: %v", err)
	}
	//log.Printf("KeyPairGen Finish")
	SystemInitialization(r.GetX0())

	MockRandom()
	msg2a, msg2b, msg2c := EncryptionA()
	r1, err1 := c.ThirdPartGeneration(ctx, &T2Generation{E1: msg2a, E2: msg2b, E3: msg2c})
	if err1 != nil {
		log.Fatalf("could not enroll: %v", err1)
	}
	//log.Printf("Enrollment Finish")
	EncryptionB(r1.GetT2())


	msg3a, msg3b := Decryption(Pw)
	r2, err2 := c.ZKProof(ctx, &ProofOfX{Flag: msg3a, TT0: msg3b})
	if err2 != nil {
		log.Fatalf("could not zero knowledge proof: %v", err2)
	}
	//log.Printf("ZeroKnowledge Finish")

	rep3a, rep3b, rep3c, rep3d, rep3e := r2.GetC0(), r2.GetC1(), r2.GetU(), r2.GetGX1R(), r2.GetX1()
	Verifier(rep3a, rep3b, rep3c, rep3d, rep3e)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg4 := T0.Marshal()
		r3, err3 := c.Rotate(ctx, &UpdateRequest{Gr: msg4})
		if err3 != nil {
			log.Fatalf("could not Rotate: %v", err3)
		}
		//log.Printf("Rotate Finish")
		for j := 0; j < 1; j++ {
			delta0, _ := PointUnmarshal(r3.GetDelta0())
			delta1, _ := PointUnmarshal(r3.GetDelta1())
			T1 = T1.Add(delta0)
			T2 = T2.Add(delta1)
		}
	}
}