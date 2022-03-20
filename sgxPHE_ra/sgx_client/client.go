package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"sgx/swu"
	"time"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/eclient"
)

var (
	n    = randomZ()
	zero = new(big.Int).SetInt64(0)
	one  = new(big.Int).SetInt64(1)
	pw   = []byte(pw_)
	ku   = randomZ()
	ks   []byte
	H0   []byte
	H1   []byte
	xs   = randomZ()

	t0 []byte
	t1 []byte
	signer []byte

	x *big.Int
	curve      = elliptic.P256()
	Gf     = swu.GF{P: curve.Params().N}
)

const (
	address = "localhost:50051"
	pw_     = "123456"
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

// 填充数据
func padding(src []byte, blockSize int) []byte {
	padNum := blockSize - len(src)%blockSize
	pad := bytes.Repeat([]byte{byte(padNum)}, padNum)
	return append(src, pad...)
}

// 去掉填充数据
func unpadding(src []byte) []byte {
	nnn := len(src)
	unPadNum := int(src[nnn-1])
	return src[:nnn-unPadNum]
}

// 加密
func encryptAES(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	src = padding(src, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(src, src)
	return src, nil
}

// 解密
func decryptAES(src []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	blockMode.CryptBlocks(src, src)
	src = unpadding(src)
	return src, nil
}

func Encryption(resp []byte) {
	buf := bytes.NewBuffer(resp)
	hr0_ := make([]byte, 32)
	hr1_ := make([]byte, 32)
	x_ := make([]byte, 32)
	buf.Read(hr0_)
	buf.Read(hr1_)
	buf.Read(x_)
	H0 = hashZ(pw, n.Bytes(), zero.Bytes())
	H1 = hashZ(pw, n.Bytes(), one.Bytes())
	hr0 := new(big.Int).SetBytes(hr0_)
	hr1 := new(big.Int).SetBytes(hr1_)
	x = new(big.Int).SetBytes(x_)
	h0 := new(big.Int).SetBytes(H0)
	h1 := new(big.Int).SetBytes(H1)
	h1ku := Gf.Mul(h1, ku)
	t0_ := Gf.Mul(h0, hr0)
	t1_ := Gf.Mul(h1ku, hr1)
	ctxt := make([]byte, aes.BlockSize+len(t0_.Bytes()))
	ks = ctxt[:aes.BlockSize]
	t0, _ = encryptAES(t0_.Bytes(), ks)
	t1, _ = encryptAES(t1_.Bytes(), ks)
}

func Validation(pw0 []byte) ([]byte, []byte, []byte, []byte, []byte) {
	h0_ := new(big.Int).SetBytes(hashZ(pw0, n.Bytes(), zero.Bytes()))
	t0_, _ := decryptAES(t0, ks)
	t1_, _ := decryptAES(t1, ks)
	c0 := Gf.Div(new(big.Int).SetBytes(t0_), h0_)
	tm_ := time.Now().Format("2006-01-02 15:04:05")
	tm := []byte(tm_)
	rt := new(big.Int).SetBytes(hashZ(tm, x.Bytes()))
	c0_ := Gf.Mul(c0, rt)
	n_ := Gf.Mul(n, rt)
	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	c0_.FillBytes(buf1)
	n_.FillBytes(buf2)
	return t0_, t1_, c0_.Bytes(), n_.Bytes(), tm
}

func Decryption(resp []byte, t1_ []byte) {
	buf := bytes.NewBuffer(resp)
	hr1_ := make([]byte, 32)
	tm := make([]byte, 19)
	buf.Read(hr1_)
	buf.Read(tm)

	rt := new(big.Int).SetBytes(hashZ(tm, x.Bytes()))
	hr1 := Gf.Div(new(big.Int).SetBytes(hr1_), rt)
	c1 := Gf.Div(new(big.Int).SetBytes(t1_), hr1)
	ku_ := Gf.Div(c1, new(big.Int).SetBytes(H1))
	if ku.Cmp(ku_) != 0 {
		fmt.Println("fail after success")
		return 
	} else {
		return
	}
}

func UpdateRecord(resp []byte, x_ *big.Int) ([]byte, []byte) {
	buf := bytes.NewBuffer(resp)
	delta0 := make([]byte, 32)
	delta1 := make([]byte, 32)
	buf.Read(delta0)
	buf.Read(delta1)
	t0_, _ := decryptAES(t0, ks)
	t1_, _ := decryptAES(t1, ks)
	t0u_ := new(big.Int).Mul(new(big.Int).SetBytes(t0_), new(big.Int).SetBytes(delta0))
	t1u_ := new(big.Int).Mul(new(big.Int).SetBytes(t1_), new(big.Int).SetBytes(delta1))
	x = x_

	ctxt := make([]byte, aes.BlockSize+len(t0u_.Bytes()))
	ks_ := ctxt[:aes.BlockSize]
	t0u, _ := encryptAES(t0u_.Bytes(), ks_)
	t1u, _ := encryptAES(t1u_.Bytes(), ks_)
	return t0u, t1u
}

func main() {
	signerArg := flag.String("s", "", "signer ID")
	serverAddr := flag.String("a", "localhost:8080", "server address")
	flag.Parse()

	// get signer command line argument
	var err error
	signer, err = hex.DecodeString(*signerArg)
	if err != nil {
		panic(err)
	}
	if len(signer) == 0 {
		flag.Usage()
		return
	}

	// Create a TLS config that verifies a certificate with embedded report.
	tlsConfig := eclient.CreateAttestationClientTLSConfig(verifyReport)

	httpGet(tlsConfig, "https://"+*serverAddr+"/secret?s=mySecret")
	
	
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 200 * time.Second}
	requestUrl := "https://localhost:8080"


	timeZeroCounter := time.Now()
	timeZero := timeZeroCounter.Sub(timeZeroCounter)
	var timeEnc, timeDec, timeUpd = timeZero, timeZero, timeZero
	for i := 0; i < 101; i++ {
		timeEncBefore := time.Now()
		buf1 := make([]byte, 32)
		buf2 := make([]byte, 32)
		xs.FillBytes(buf1)
		n.FillBytes(buf2)
		EncMsg := [][]byte{buf1, buf2}
		EncMsgTuple := bytes.Join(EncMsg, []byte(""))
		EncReq := bytes.NewReader(EncMsgTuple)
		EncResp, err := client.Post(requestUrl+"/enc", "application/x-www-form-urlencoded", EncReq)
		if err != nil {
			panic(err)
		}
		defer EncResp.Body.Close()
		// if EncResp.StatusCode != http.StatusOK {
		// 	fmt.Println(EncResp.Body)
		// 	panic(EncResp.Status)
		// }
		EncRespContent, _ := ioutil.ReadAll(EncResp.Body)

		Encryption(EncRespContent)
		timeDecBefore := time.Now()

		t0_, t1_, c0_, n_, tm := Validation(pw)
		DecMsg := [][]byte{c0_, n_, tm}
		DecMsgTuple := bytes.Join(DecMsg, []byte(""))
		DecReq := bytes.NewReader(DecMsgTuple)
		DecResp, err2 := client.Post(requestUrl+"/dec", "application/x-www-form-urlencoded", DecReq)
		if err2 != nil {
			panic(err2)
		}
		defer DecResp.Body.Close()
		DecRespContent, _ := ioutil.ReadAll(DecResp.Body)

		Decryption(DecRespContent, t1_)

		timeUpdBefore := time.Now()
		buf3 := make([]byte, 32)
		x_ := randomZ()
		x_.FillBytes(buf3)
		UpdMsg := [][]byte{buf2, buf3}
		UpdMsgTuple := bytes.Join(UpdMsg, []byte(""))
		UpdReq := bytes.NewReader(UpdMsgTuple)
		UpdResp, err3 := client.Post(requestUrl+"/upd", "application/x-www-form-urlencoded", UpdReq)
		if err3 != nil {
			panic(err3)
		}
		defer UpdResp.Body.Close()
		UpdRespContent, _ := ioutil.ReadAll(UpdResp.Body)
		for j := 0; j < 100; j++ {
			t0Ex, _ := encryptAES(t0_, ks)
			t1Ex, _ := encryptAES(t1_, ks)
			UpdateRecord(UpdRespContent, x_)
			t0 = t0Ex
			t1 = t1Ex
		}

		timeUpdAfter := time.Now()

		if i != 0 {
			timeEnc += timeDecBefore.Sub(timeEncBefore)
			// timeEncPost := timeEncPostAfter.Sub(timeEncPostBefore)
			timeDec += timeUpdBefore.Sub(timeDecBefore)
			timeUpd += timeUpdAfter.Sub(timeUpdBefore)
		}
		
	}
	fmt.Println(timeEnc/100, timeDec/100, timeUpd/100)

}

func verifyReport(report attestation.Report) error {
	// You can either verify the UniqueID or the tuple (SignerID, ProductID, SecurityVersion, Debug).

	if report.SecurityVersion < 1 {
		return errors.New("invalid security version")
	}
	if binary.LittleEndian.Uint16(report.ProductID) != 1 {
		return errors.New("invalid product")
	}
	if !bytes.Equal(report.SignerID, signer) {
		return errors.New("invalid signer")
	}

	// For production, you must also verify that report.Debug == false

	return nil
}

func httpGet(tlsConfig *tls.Config, url string) []byte {
	client := http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		panic(resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return body
}