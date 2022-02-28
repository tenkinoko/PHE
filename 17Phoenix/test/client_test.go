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

	. "18phe/client"
	. "18phe/phe"
	. "18phe/utils"
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

	fmt.Println(r2.GetFlag())
}