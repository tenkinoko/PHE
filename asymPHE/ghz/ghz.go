package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"runtime"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	. "simple_phe/phe"
	. "simple_phe/server"

	"github.com/bojand/ghz/printer"
	"github.com/bojand/ghz/runner"
	"github.com/golang/protobuf/proto"
)

const (
	address = "localhost:50051"
)

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
	const datafile = "../credentials/"
	const protofile = "../phe/phe.proto"
	_, filename, _, _ := runtime.Caller(0)
	credpath := path.Join(path.Dir(filename), datafile)
	protopath := path.Join(path.Dir(filename), protofile)
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
	c := NewKeyPairGenClient(conn)

	// Benchmark needs more time
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

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
	_, err3 := c.Rotate(ctx, &UpdateRequest{Gr: msg4})
	if err3 != nil {
		log.Fatalf("could not Rotate: %v", err3)
	}
	// 组装BinaryData
	// item := T2Generation{E1: msg2a, E2: msg2b, E3: msg2c}
	// item := ProofOfX{TT0: msg3b, Flag: msg3a}
	item := UpdateRequest{Gr: msg4}
	buf := proto.Buffer{}
	err111 := buf.EncodeMessage(&item)
	if err111 != nil {
		log.Fatal(err111)
		return
	}
	report, err222 := runner.Run(
		// 基本配置 call host proto文件 data
		"phe.KeyPairGen.Rotate", //  'package.Service/method' or 'package.Service.Method'
		"localhost:50051",
		runner.WithProtoFile(protopath, []string{}),
		runner.WithBinaryData(buf.Bytes()),
		runner.WithInsecure(false),
		runner.WithSkipTLSVerify(true),
		runner.WithCertificate(credpath+"/client.crt", credpath+"/client.key"),
		runner.WithTotalRequests(10000),
		// 并发参数
		runner.WithConcurrencySchedule(runner.ScheduleConst),
		runner.WithConcurrency(400),
	)
	if err222 != nil {
		log.Fatal(err222)
		return
	}
	// 指定输出路径
	file, err333 := os.Create("report.html")
	if err333 != nil {
		log.Fatal(err333)
		return
	}
	rp := printer.ReportPrinter{
		Out:    file,
		Report: report,
	}
	// 指定输出格式
	_ = rp.Print("html")
}
