package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

var (
	randReader = rand.Reader
	curve      = elliptic.P256()
	curveG     = new(Point).ScalarBaseMultInt(new(big.Int).SetUint64(1)).Marshal()
	//gf         = swu.GF{P: curve.Params().N}

	commonPrefix     = []byte{0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45} //VRGLPHE
	dhc0             = append(commonPrefix, 0x31)
	dhc1             = append(commonPrefix, 0x32)
	dhs0             = append(commonPrefix, 0x33)
	dhs1             = append(commonPrefix, 0x34)
	proofOk          = append(commonPrefix, 0x35)
	proofError       = append(commonPrefix, 0x36)
	encrypt          = append(commonPrefix, 0x37)
	kdfInfoZ         = append(commonPrefix, 0x38)
	kdfInfoClientKey = append(commonPrefix, 0x39)
)

const (
	zLen = 32
)

func hash(domain []byte, tuple ...[]byte) []byte {
	hash := sha512.New()
	/* #nosec */
	hash.Write(domain)
	for _, t := range tuple {
		/* #nosec */
		hash.Write(t)
	}
	return hash.Sum(nil)
}

func initKdf(domain []byte, tuple ...[]byte) io.Reader {
	key := hash(nil, tuple...)

	return hkdf.New(sha512.New, key, domain, kdfInfoZ)

}

func random256() (z *big.Int){
	rz := makeZ(randReader)
	for z == nil {

		// If the scalar is out of range, sample another random number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(randReader)
		} else {
			z = rz
		}
	}
	return
}

func Random256() []byte{
	return random256().Bytes()
}

func makeZ(reader io.Reader) *big.Int {
	buf := make([]byte, zLen)
	n, err := reader.Read(buf)
	if err != nil || n != zLen {
		panic("random read failed")
	}
	return new(big.Int).SetBytes(buf)
}

func HashPwd(pw1 []byte, n1 []byte, num1 int) []byte{
	var str0 string
	if num1 == 0 {
		str0 = "0"
	} else {
		str0 = "1"
	}
	byte0 := []byte(str0)
	pwn0 := [][]byte{pw1, n1, byte0}
	pwn0Bytes := bytes.Join(pwn0, []byte{})
	Hpwn0 := sha1.Sum(pwn0Bytes)
	Hpwn0_ := Hpwn0[:]
	return Hpwn0_
}

// hashZ maps arrays of bytes to an integer less than curve's N parameter
func hashZ(domain []byte, data ...[]byte) (z *big.Int) {
	xof := initKdf(domain, data...)
	rz := makeZ(xof)

	for z == nil {
		// If the scalar is out of range, extract another number.
		if rz.Cmp(curve.Params().N) >= 0 {
			rz = makeZ(xof)
		} else {
			z = rz
		}
	}
	return
}

func padZ(z []byte) []byte {
	if len(z) == zLen {
		return z
	}

	newZ := make([]byte, zLen)
	copy(newZ[zLen-len(z):], z)
	return newZ
}