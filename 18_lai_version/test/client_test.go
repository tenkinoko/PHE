package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	. "18phe/client"
	. "18phe/phe"
	. "18phe/utils"
)

var (
	pwd = []byte("Password")
)

const (
	address = "localhost:50051"
)

func Test_Workflow(t *testing.T) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		log.Fatalf("could not request get enrollment: %v", err)
	}
	log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(r1)
	rec, key, err := nc.EnrollAccount(pwd, enrollment)

	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
	r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
		Ns: msg3b,
		C0: msg3a,
	})
	if err2 != nil {
		log.Fatalf("could not request verify password: %v", err)
	}
	log.Printf("VerifyPassword Finish")
	res, _ := proto.Marshal(r2)

	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	fmt.Println(bytes.Equal(key, keyDec))
	require.Equal(t, key, keyDec)

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		log.Fatalf("could not request update: %v", err)
	}
	log.Printf("Rotate Finish")
	token, _ := proto.Marshal(r4)
	err5 := nc.Rotate(token)
	require.NoError(t, err5)

	_, _ = UpdateRecord(rec, token)

}

func Benchmark_Workflow(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	var nc *ShadowClient
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg1 := "requestPublicKey"
		r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
		if err != nil {
			log.Fatalf("could not request public key: %v", err)
		}
		//log.Printf("ReceivePubkey Finish")
		nc, _ = NewClient(r.GetPublicKey(), RandomZ().Bytes())

		msg2 := "requestGenEnrollment"
		r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
		if err1 != nil {
			b.Fatalf("could not request get enrollment: %v", err)
		}
		//log.Printf("GetEnrollment Finish")
		enrollment, _ := proto.Marshal(&EnrollmentResponse{
			Ns:    r1.GetNs(),
			C0:    r1.GetC0(),
			C1:    r1.GetC1(),
			Proof: r1.GetProof(),
		})
		rec, key, err := nc.EnrollAccount(pwd, enrollment)

		msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
		r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
			Ns: msg3b,
			C0: msg3a,
		})
		if err2 != nil {
			b.Fatalf("could not request verify password: %v", err)
		}
		//log.Printf("VerifyPassword Finish")
		res, _ := proto.Marshal(&VerifyPasswordResponse{
			Res:   r2.GetRes(),
			C1:    r2.GetC1(),
			Proof: r2.GetProof(),
		})

		keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
		bytes.Equal(key, keyDec)

		msg4 := "requestUpdate"
		r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
		if err4 != nil {
			b.Fatalf("could not request update: %v", err)
		}
		token, _ := proto.Marshal(r4)
		nc.Rotate(token)
		_, _ = UpdateRecord(rec, token)
	}
}

func Benchmark_RequestPublicKey(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	var nc *ShadowClient
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg1 := "requestPublicKey"
		r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
		if err != nil {
			log.Fatalf("could not request public key: %v", err)
		}
		//log.Printf("ReceivePubkey Finish")
		nc, _ = NewClient(r.GetPublicKey(), RandomZ().Bytes())
	}
	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	rec, key, err := nc.EnrollAccount(pwd, enrollment)

	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
	r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
		Ns: msg3b,
		C0: msg3a,
	})
	if err2 != nil {
		b.Fatalf("could not request verify password: %v", err)
	}
	//log.Printf("VerifyPassword Finish")
	res, _ := proto.Marshal(&VerifyPasswordResponse{
		Res:   r2.GetRes(),
		C1:    r2.GetC1(),
		Proof: r2.GetProof(),
	})

	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	bytes.Equal(key, keyDec)

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		b.Fatalf("could not request update: %v", err)
	}
	token, _ := proto.Marshal(r4)
	nc.Rotate(token)
	_, _ = UpdateRecord(rec, token)
}

func Benchmark_ZkAtEnc(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	//var rec, key []byte
	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		nc.EnrollAccountOnlyZK(pwd, enrollment)
	}

}

func Benchmark_GetEnrollment(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	var rec, key []byte
	b.ReportAllocs()
	b.ResetTimer()
	var enrollment []byte
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg2 := "requestGenEnrollment"
		r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
		if err1 != nil {
			b.Fatalf("could not request get enrollment: %v", err)
		}
		//log.Printf("GetEnrollment Finish")
		enrollment, _ = proto.Marshal(&EnrollmentResponse{
			Ns:    r1.GetNs(),
			C0:    r1.GetC0(),
			C1:    r1.GetC1(),
			Proof: r1.GetProof(),
		})
	}

	rec, key, err = nc.EnrollAccount(pwd, enrollment)

	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
	r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
		Ns: msg3b,
		C0: msg3a,
	})
	if err2 != nil {
		b.Fatalf("could not request verify password: %v", err)
	}
	//log.Printf("VerifyPassword Finish")
	res, _ := proto.Marshal(&VerifyPasswordResponse{
		Res:   r2.GetRes(),
		C1:    r2.GetC1(),
		Proof: r2.GetProof(),
	})

	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	bytes.Equal(key, keyDec)

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		b.Fatalf("could not request update: %v", err)
	}
	token, _ := proto.Marshal(r4)
	nc.Rotate(token)
	_, _ = UpdateRecord(rec, token)
}

func Benchmark_EnrollAccount(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	var rec, key []byte

	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		rec, key, err = nc.EnrollAccount(pwd, enrollment)
	}
	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
	r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
		Ns: msg3b,
		C0: msg3a,
	})
	if err2 != nil {
		b.Fatalf("could not request verify password: %v", err)
	}
	//log.Printf("VerifyPassword Finish")
	res, _ := proto.Marshal(&VerifyPasswordResponse{
		Res:   r2.GetRes(),
		C1:    r2.GetC1(),
		Proof: r2.GetProof(),
	})

	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	bytes.Equal(key, keyDec)

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		b.Fatalf("could not request update: %v", err)
	}
	token, _ := proto.Marshal(r4)
	nc.Rotate(token)
	_, _ = UpdateRecord(rec, token)
}

func Benchmark_Verify(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	rec, key, err := nc.EnrollAccount(pwd, enrollment)

	var r2 *VerifyPasswordResponse
	var err2 error
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
		r2, err2 = c.VerifyPassword(ctx, &VerifyPasswordRequest{
			Ns: msg3b,
			C0: msg3a,
		})
		if err2 != nil {
			b.Fatalf("could not request verify password: %v", err)
		}
	}
	//log.Printf("VerifyPassword Finish")
	res, _ := proto.Marshal(&VerifyPasswordResponse{
		Res:   r2.GetRes(),
		C1:    r2.GetC1(),
		Proof: r2.GetProof(),
	})

	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	bytes.Equal(key, keyDec)

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		b.Fatalf("could not request update: %v", err)
	}
	token, _ := proto.Marshal(r4)
	nc.Rotate(token)
	_, _ = UpdateRecord(rec, token)
}

func Benchmark_VerifyOnR(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	rec, key, err := nc.EnrollAccount(pwd, enrollment)

	var r2 *VerifyPasswordResponse
	var err2 error
	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MockRandom()

		r2, err2 = c.VerifyPassword(ctx, &VerifyPasswordRequest{
			Ns: msg3b,
			C0: msg3a,
		})

	}
	if err2 != nil {
		b.Fatalf("could not request verify password: %v", err)
	}

	//log.Printf("VerifyPassword Finish")
	res, _ := proto.Marshal(&VerifyPasswordResponse{
		Res:   r2.GetRes(),
		C1:    r2.GetC1(),
		Proof: r2.GetProof(),
	})

	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	bytes.Equal(key, keyDec)

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		b.Fatalf("could not request update: %v", err)
	}
	token, _ := proto.Marshal(r4)
	nc.Rotate(token)
	_, _ = UpdateRecord(rec, token)
}

func Benchmark_DecryptWrong(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	rec, key, err := nc.EnrollAccount(pwd, enrollment)

	b.ReportAllocs()
	b.ResetTimer()
	//log.Printf("VerifyPassword Finish")
	for i := 0; i < b.N; i++ {
		MockRandom()
		pwd_ := []byte("Wrong Password")
		msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd_, rec)
		r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
			Ns: msg3b,
			C0: msg3a,
		})
		if err2 != nil {
			b.Fatalf("could not request verify password: %v", err)
		}



		res, _ := proto.Marshal(&VerifyPasswordResponse{
			Res:   r2.GetRes(),
			C1:    r2.GetC1(),
			Proof: r2.GetProof(),
		})

		keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
		bytes.Equal(key, keyDec)
	}

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		b.Fatalf("could not request update: %v", err)
	}
	token, _ := proto.Marshal(r4)
	nc.Rotate(token)
	_, _ = UpdateRecord(rec, token)
}

func Benchmark_CheckAndDecrypt(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	rec, key, err := nc.EnrollAccount(pwd, enrollment)

	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
	r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
		Ns: msg3b,
		C0: msg3a,
	})
	if err2 != nil {
		b.Fatalf("could not request verify password: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	//log.Printf("VerifyPassword Finish")
	for i := 0; i < b.N; i++ {
		MockRandom()
		res, _ := proto.Marshal(&VerifyPasswordResponse{
			Res:   r2.GetRes(),
			C1:    r2.GetC1(),
			Proof: r2.GetProof(),
		})

		keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
		bytes.Equal(key, keyDec)
	}

	msg4 := "requestUpdate"
	r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
	if err4 != nil {
		b.Fatalf("could not request update: %v", err)
	}
	token, _ := proto.Marshal(r4)
	nc.Rotate(token)
	_, _ = UpdateRecord(rec, token)
}

func Benchmark_Update(b *testing.B) {
	const datafile = "../credentials/"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	// TLS Based on CA
	cert, err := tls.LoadX509KeyPair(credpath+"/client.crt", credpath+"/client.key")
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
	c := NewPheWorkflowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*60)
	defer cancel()

	msg1 := "requestPublicKey"
	r, err := c.ReceivePubkey(ctx, &PubkeyRecord{Flag: msg1})
	if err != nil {
		log.Fatalf("could not request public key: %v", err)
	}
	//log.Printf("ReceivePubkey Finish")
	nc, _ := NewClient(r.GetPublicKey(), RandomZ().Bytes())

	msg2 := "requestGenEnrollment"
	r1, err1 := c.GetEnrollment(ctx, &GetEnrollRecord{Flag: msg2})
	if err1 != nil {
		b.Fatalf("could not request get enrollment: %v", err)
	}
	//log.Printf("GetEnrollment Finish")
	enrollment, _ := proto.Marshal(&EnrollmentResponse{
		Ns:    r1.GetNs(),
		C0:    r1.GetC0(),
		C1:    r1.GetC1(),
		Proof: r1.GetProof(),
	})
	rec, key, err := nc.EnrollAccount(pwd, enrollment)

	msg3a, msg3b, _ := nc.CreateVerifyPasswordRequest(pwd, rec)
	r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
		Ns: msg3b,
		C0: msg3a,
	})
	if err2 != nil {
		b.Fatalf("could not request verify password: %v", err)
	}
	res, _ := proto.Marshal(&VerifyPasswordResponse{
		Res:   r2.GetRes(),
		C1:    r2.GetC1(),
		Proof: r2.GetProof(),
	})
	keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	bytes.Equal(key, keyDec)

	b.ReportAllocs()
	b.ResetTimer()
	//log.Printf("VerifyPassword Finish")
	for i := 0; i < b.N; i++ {
		MockRandom()
		msg4 := "requestUpdate"
		r4, err4 := c.Rotate(ctx, &UpdateRequest{Flag: msg4})
		if err4 != nil {
			b.Fatalf("could not request update: %v", err)
		}
		token, _ := proto.Marshal(r4)
		nc.Rotate(token)
		for i := 0; i < 1; i++ {
			_, _ = UpdateRecord(rec, token)
		}
	}
}
