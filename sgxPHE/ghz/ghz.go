package main

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log"
	"math/big"
	"os"
	"path"
	"runtime"

	pb "sgx/sgx"

	"github.com/bojand/ghz/printer"
	"github.com/bojand/ghz/runner"
	"github.com/golang/protobuf/proto"
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
	_, filename, _, _ := runtime.Caller(0)
	const protofile = "../sgx/sgx.proto"
	protopath := path.Join(path.Dir(filename), protofile)
	// 组装BinaryData
	// item := pb.NegoRequest{Xs: randomZ().Bytes(), N: randomZ().Bytes()}
	// item := pb.DecryptRequest{
	// 	C0: randomZ().Bytes(),
	// 	N:  randomZ().Bytes(),
	// 	Tm: randomZ().Bytes(),
	// }
	item := pb.UpdateRequest{
		N:  randomZ().Bytes(),
		Xs: randomZ().Bytes(),
	}
	buf := proto.Buffer{}
	err := buf.EncodeMessage(&item)
	if err != nil {
		log.Fatal(err)
		return
	}
	report, err := runner.Run(
		// 基本配置 call host proto文件 data
		"sgx.PHE.Update", //  'package.Service/method' or 'package.Service.Method'
		"localhost:50051",
		runner.WithProtoFile(protopath, []string{}),
		runner.WithBinaryData(buf.Bytes()),
		runner.WithInsecure(true),
		runner.WithTotalRequests(10000),
		// 并发参数
		runner.WithConcurrencySchedule(runner.ScheduleConst),
		runner.WithConcurrency(400),
	)
	if err != nil {
		log.Fatal(err)
		return
	}
	// 指定输出路径
	file, err := os.Create("report.html")
	if err != nil {
		log.Fatal(err)
		return
	}
	rp := printer.ReportPrinter{
		Out:    file,
		Report: report,
	}
	// 指定输出格式
	_ = rp.Print("html")
}
