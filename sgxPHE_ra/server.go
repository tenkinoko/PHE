package main

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	//"log"
	"math/big"
	"net/http"
	"sgx/swu"
	"time"

	"github.com/edgelesssys/ego/enclave"
)

var (
	xks1 = randomZ()
	xks2 = randomZ()
	zero = new(big.Int).SetInt64(0)
	one  = new(big.Int).SetInt64(1)
	xk   *big.Int
	xv   *big.Int
	hr0  []byte
	hr1  []byte
	curve      = elliptic.P256()
	Gf     = swu.GF{P: curve.Params().N}
)


func main() {
	// Create a TLS config with a self-signed certificate and an embedded report.
	tlsCfg, err := enclave.CreateAttestationServerTLSConfig()
	if err != nil {
		panic(err)
	}

	// Create HTTPS server.

	http.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%v sent secret %v\n", r.RemoteAddr, r.URL.Query()["s"])
	})
	http.HandleFunc("/enc", EncryptionHandler)
	http.HandleFunc("/dec", DecryptionHandler)
	http.HandleFunc("/upd", UpdateHandler)
	server := http.Server{Addr: "0.0.0.0:8080", TLSConfig: tlsCfg}

	fmt.Println("listening ...")
	err = server.ListenAndServeTLS("", "")
	fmt.Println(err)
	

	// log.Printf("server listening...")
	// if err := http.ListenAndServe(":8080", nil); err != nil {
	// 	log.Fatal(err)
	// }
}

func createCertificate() ([]byte, crypto.PrivateKey) {
	template := &x509.Certificate{
		SerialNumber: &big.Int{},
		Subject:      pkix.Name{CommonName: "localhost"},
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	return cert, priv
}

func EncryptionHandler(w http.ResponseWriter, r *http.Request) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	msg := bytes.NewBuffer(buf)
	xs := make([]byte, 32)
	n := make([]byte, 32)
	msg.Read(xs)
	msg.Read(n)
	xk = new(big.Int).SetBytes(hashZ(xs, xks1.Bytes(), zero.Bytes()))
	xv = new(big.Int).SetBytes(hashZ(xs, xks2.Bytes(), zero.Bytes()))
	hr0 = hashZ(xk.Bytes(), n, zero.Bytes())
	hr1 = hashZ(xk.Bytes(), n, one.Bytes())
	ReplyMsg := [][]byte{hr0, hr1, xk.Bytes()}
	Reply := bytes.Join(ReplyMsg, []byte(""))
	w.Write(Reply)
}

func DecryptionHandler(w http.ResponseWriter, r *http.Request) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	msg := bytes.NewBuffer(buf)
	c0__ := make([]byte, 32)
	n__ := make([]byte, 32)
	tm := make([]byte, 19)
	msg.Read(c0__)
	msg.Read(n__)
	msg.Read(tm)
	c0_ := new(big.Int).SetBytes(c0__)
	n_ := new(big.Int).SetBytes(n__)
	if xk == nil {
		xk = randomZ()
	}
	rt := new(big.Int).SetBytes(hashZ(tm, xk.Bytes()))
	c0 := Gf.Div(c0_, rt)
	n := Gf.Div(n_, rt)
	hxn0 := new(big.Int).SetBytes(hashZ(xk.Bytes(), n.Bytes(), zero.Bytes()))
	hr1_ := make([]byte, 32)
	if c0.Cmp(hxn0) == 0 {
		Gf.Mul(new(big.Int).SetBytes(hr1), rt).FillBytes(hr1_)
	} else {
		hr1_ = []byte("000000")
		panic(errors.New("Failed in decryption!"))
	}
	ReplyMsg := [][]byte{hr1_, tm}
	// log.Println(hr1_, tm)
	Reply := bytes.Join(ReplyMsg, []byte(""))
	w.Write(Reply)
}

func UpdateHandler(w http.ResponseWriter, r *http.Request) {
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	msg := bytes.NewBuffer(buf)
	xs := make([]byte, 32)
	n := make([]byte, 32)
	msg.Read(n)
	msg.Read(xs)
	xks1 = randomZ()
	xks2 = randomZ()
	xk_ := new(big.Int).SetBytes(hashZ(xs, xks1.Bytes(), zero.Bytes()))
	xv_ := new(big.Int).SetBytes(hashZ(xs, xks2.Bytes(), zero.Bytes()))
	xv = xv_
	hxkn0 := hashZ(xk.Bytes(), n, zero.Bytes())
	hxkn1 := hashZ(xk.Bytes(), n, one.Bytes())
	hxkn0_ := hashZ(xk_.Bytes(), n, zero.Bytes())
	hxkn1_ := hashZ(xk_.Bytes(), n, one.Bytes())
	delta0 := make([]byte, 32)
	delta1 := make([]byte, 32)
	Gf.Mul(new(big.Int).SetBytes(hxkn0_), new(big.Int).SetBytes(hxkn0)).FillBytes(delta0)
	Gf.Mul(new(big.Int).SetBytes(hxkn1_), new(big.Int).SetBytes(hxkn1)).FillBytes(delta1)
	ReplyMsg := [][]byte{delta0, delta1}
	Reply := bytes.Join(ReplyMsg, []byte(""))
	w.Write(Reply)
}

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
