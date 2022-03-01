package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"runtime"
	"time"

	. "18phe/client"
	. "18phe/phe"
	. "18phe/utils"
	"github.com/bojand/ghz/printer"
	"github.com/bojand/ghz/runner"
	"github.com/golang/protobuf/proto"
)

var (
	pwd = []byte("Password")
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
	if !r2.GetFlag() {
		log.Fatalf("cannot pass")
	}
	r3, err3 := c.Rotation(ctx, &RotationC{Flag: RandomZ().Bytes()})
	if err3 != nil {
		log.Fatalf("could not validate: %v", err3)
	}
	Update(r3.GetAlpha(), r3.GetBeta(), r3.GetGamma(), r3.GetZeta(), h, z, r1.GetHs())
	//r2, err2 := c.VerifyPassword(ctx, &VerifyPasswordRequest{
	//	Ns: msg3b,
	//	C0: msg3a,
	//})
	//if err2 != nil {
	//	log.Fatalf("could not request verify password: %v", err)
	//}
	//log.Printf("VerifyPassword Finish")
	//res, _ := proto.Marshal(r2)
	//
	//keyDec, _ := nc.CheckResponseAndDecrypt(pwd, rec, res)
	//fmt.Println(bytes.Equal(key, keyDec))

	// 组装BinaryData
	item := EnrollmentC{Un: un}
	buf := proto.Buffer{}
	err111 := buf.EncodeMessage(&item)
	if err111 != nil {
		log.Fatal(err111)
		return
	}
	report, err222 := runner.Run(
		// 基本配置 call host proto文件 data
		"phe.phe_workflow.Enrollment", //  'package.Service/method' or 'package.Service.Method'
		"localhost:50051",
		runner.WithProtoFile("..\\phe\\phe.proto", []string{}),
		runner.WithBinaryData(buf.Bytes()),
		runner.WithInsecure(false),
		runner.WithSkipTLSVerify(true),
		runner.WithCertificate("..\\..\\17Phoenix\\credentials\\client.crt", "..\\credentials\\client.key"),
		runner.WithTotalRequests(10000),
		// 并发参数
		runner.WithConcurrencySchedule(runner.ScheduleLine),
		runner.WithConcurrencyStep(1),
		runner.WithConcurrencyStart(399),
		runner.WithConcurrencyEnd(400),
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
