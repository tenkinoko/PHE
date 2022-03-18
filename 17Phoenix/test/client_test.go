package phe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"log"
	"path"
	"runtime"
	"testing"
	"time"

	. "18phe/client"
	. "18phe/phe"
	. "18phe/utils"
)

const (
	address 	= "localhost:50051"
)


func Test_Workflow(t *testing.T){
	var opts []grpc.DialOption
	if Https {
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
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithTransportCredentials(cred),
		}
	} else {
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithInsecure(),
			grpc.WithBlock(),
		}
	}
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer func(conn *grpc.ClientConn) {
		err_ := conn.Close()
		if err_ != nil {

		}
	}(conn)
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r0, err0 := c.Setup(ctx, &SetupC{Flag: RandomZ().Bytes()})
	if err0 != nil {
		log.Fatalf("could not setup: %v", err0)
	}
	h, z := r0.GetH(), r0.GetZ()

	SetupClient()
	un := EnrollmentClient(z)
	r1, err1 := c.Enrollment(ctx, &EnrollmentC{Un: un})
	if err1 != nil {
		log.Fatalf("could not enroll: %v", err1)
	}
	C1m, C2m, C3m := ValidationClient(r1.GetHs(), r1.GetNs(), h, z)

	r2, err2 := c.Validation(ctx, &ValidationC{
		C1: C1m,
		C2: C2m,
		C3: C3m,
	})
	if err2 != nil {
		log.Fatalf("could not validate: %v", err2)
	}
	if ZKProof(r2.GetXH(), r2.GetXC1(), r2.GetXGS(), r2.GetXS(), r2.GetXKS(), h, r1.GetNs()) {
		log.Fatalf("cannot pass")
	}
	r3, err3 := c.Rotation(ctx, &RotationC{Flag: RandomZ().Bytes()})
	if err3 != nil {
		log.Fatalf("could not validate: %v", err3)
	}
	Update(r3.GetAlpha(), r3.GetBeta(), r3.GetGamma(), r3.GetZeta(), h, z, r1.GetHs())
}

func Benchmark_Enrollment(b *testing.B){
	var opts []grpc.DialOption
	if Https {
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
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithTransportCredentials(cred),
		}
	} else {
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithInsecure(),
			grpc.WithBlock(),
		}
	}

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer func(conn *grpc.ClientConn) {
		err_ := conn.Close()
		if err_ != nil {

		}
	}(conn)
	c := NewPheWorkflowClient(conn)
	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()



	r0, err0 := c.Setup(ctx, &SetupC{Flag: RandomZ().Bytes()})
	if err0 != nil {
		log.Fatalf("could not setup: %v", err0)
	}
	h, z := r0.GetH(), r0.GetZ()

	MockRandom()
	SetupClient()
	b.ReportAllocs()
	b.ResetTimer()
	var hs []byte
	var ns []byte
	for i := 0; i < b.N; i++ {
		MockRandom()
		un := EnrollmentClient(z)
		r1, err1 := c.Enrollment(ctx, &EnrollmentC{Un: un})
		if err1 != nil {
			log.Fatalf("could not enroll: %v", err1)
		}
		hs = r1.GetHs()
		ns = r1.GetNs()
	}
	MockRandom()
	C1m, C2m, C3m := ValidationClient(hs, ns, h, z)

	r2, err2 := c.Validation(ctx, &ValidationC{
		C1: C1m,
		C2: C2m,
		C3: C3m,
	})
	if err2 != nil {
		log.Fatalf("could not validate: %v", err2)
	}
	if ZKProof(r2.GetXH(), r2.GetXC1(), r2.GetXGS(), r2.GetXS(), r2.GetXKS(), h, ns) {
		log.Fatalf("cannot pass")
	}
	r3, err3 := c.Rotation(ctx, &RotationC{Flag: RandomZ().Bytes()})
	if err3 != nil {
		log.Fatalf("could not validate: %v", err3)
	}
	Update(r3.GetAlpha(), r3.GetBeta(), r3.GetGamma(), r3.GetZeta(), h, z, hs)
}

func Benchmark_Validation(b *testing.B){
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
	var opts []grpc.DialOption
	if Https {
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithTransportCredentials(cred),
		}
	} else {
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithInsecure(),
			grpc.WithBlock(),
		}
	}

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer func(conn *grpc.ClientConn) {
		err_ := conn.Close()
		if err_ != nil {

		}
	}(conn)
	c := NewPheWorkflowClient(conn)
	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()



	r0, err0 := c.Setup(ctx, &SetupC{Flag: RandomZ().Bytes()})
	if err0 != nil {
		log.Fatalf("could not setup: %v", err0)
	}
	h, z := r0.GetH(), r0.GetZ()

	MockRandom()
	SetupClient()
	un := EnrollmentClient(z)
	r1, err1 := c.Enrollment(ctx, &EnrollmentC{Un: un})
	if err1 != nil {
		log.Fatalf("could not enroll: %v", err1)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		C1m, C2m, C3m := ValidationClient(r1.GetHs(), r1.GetNs(), h, z)

		r2, err2 := c.Validation(ctx, &ValidationC{
			C1: C1m,
			C2: C2m,
			C3: C3m,
		})
		if err2 != nil {
			log.Fatalf("could not validate: %v", err2)
		}
		if ZKProof(r2.GetXH(), r2.GetXC1(), r2.GetXGS(), r2.GetXS(), r2.GetXKS(), h, r1.GetNs()) {
			log.Fatalf("cannot pass")
		}
	}
	MockRandom()
	r3, err3 := c.Rotation(ctx, &RotationC{Flag: RandomZ().Bytes()})
	if err3 != nil {
		log.Fatalf("could not validate: %v", err3)
	}
	Update(r3.GetAlpha(), r3.GetBeta(), r3.GetGamma(), r3.GetZeta(), h, z, r1.GetHs())
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

	var opts []grpc.DialOption
	if Https {
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithTransportCredentials(cred),
		}
	} else {
		opts = []grpc.DialOption{
			// credentials.
			grpc.WithInsecure(),
			grpc.WithBlock(),
		}
	}

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer func(conn *grpc.ClientConn) {
		err_ := conn.Close()
		if err_ != nil {

		}
	}(conn)
	c := NewPheWorkflowClient(conn)
	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()



	r0, err0 := c.Setup(ctx, &SetupC{Flag: RandomZ().Bytes()})
	if err0 != nil {
		log.Fatalf("could not setup: %v", err0)
	}
	h, z := r0.GetH(), r0.GetZ()

	MockRandom()
	SetupClient()
	un := EnrollmentClient(z)
	r1, err1 := c.Enrollment(ctx, &EnrollmentC{Un: un})
	if err1 != nil {
		log.Fatalf("could not enroll: %v", err1)
	}
	C1m, C2m, C3m := ValidationClient(r1.GetHs(), r1.GetNs(), h, z)

	r2, err2 := c.Validation(ctx, &ValidationC{
		C1: C1m,
		C2: C2m,
		C3: C3m,
	})
	if err2 != nil {
		log.Fatalf("could not validate: %v", err2)
	}
	if ZKProof(r2.GetXH(), r2.GetXC1(), r2.GetXGS(), r2.GetXS(), r2.GetXKS(), h, r1.GetNs()) {
		log.Fatalf("cannot pass")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		r3, err3 := c.Rotation(ctx, &RotationC{Flag: RandomZ().Bytes()})
		if err3 != nil {
			log.Fatalf("could not validate: %v", err3)
		}
		for j := 0; j < UpdCount; j++ {
			MockRandom()
			Update(r3.GetAlpha(), r3.GetBeta(), r3.GetGamma(), r3.GetZeta(), h, z, r1.GetHs())
		}

	}
}