package ghz

import (
	"crypto/rand"
	"crypto/sha1"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/bojand/ghz/printer"
	"github.com/bojand/ghz/runner"
	"github.com/golang/protobuf/proto"
	pb "sgx/sgx"
)



func hashZ(domain []byte, tuple ...[]byte) []byte {
	hash := sha1.New()
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

// 官方文档 https://ghz.sh/docs/intro.html
func main() {
	// 组装BinaryData
	item := pb.NegoRequest{
		Xs: randomZ().Bytes(),
		N:  randomZ().Bytes(),
	}
	buf := proto.Buffer{}
	err := buf.EncodeMessage(&item)
	if err != nil {
		log.Fatal(err)
		return
	}
	report, err := runner.Run(
		// 基本配置 call host proto文件 data
		"helloworld.Greeter.SayHello", //  'package.Service/method' or 'package.Service.Method'
		"localhost:50051",
		runner.WithProtoFile("../helloworld/helloworld/hello_world.proto", []string{}),
		runner.WithBinaryData(buf.Bytes()),
		runner.WithInsecure(true),
		runner.WithTotalRequests(10000),
		// 并发参数
		runner.WithConcurrencySchedule(runner.ScheduleLine),
		runner.WithConcurrencyStep(10),
		runner.WithConcurrencyStart(5),
		runner.WithConcurrencyEnd(100),
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
