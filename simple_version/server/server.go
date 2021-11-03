package server

import (
	//"context"
	//"crypto/tls"
	//"crypto/x509"
	//"fmt"
	//"google.golang.org/grpc"
	//"google.golang.org/grpc/credentials"
	//"io/ioutil"
	//"log"
	"math/big"
	//"path"
	//"runtime"
	//"time"

	. "simple_phe/utils"

	//. "simple_phe/phe"
)

var (
	x0 *big.Int
	X0 *Point
	n  []byte
	r  []byte
	k  []byte
	Pw []byte
	numZero []byte
	numOne []byte

	T0 *Point
	T1 *Point
	T2 *Point
)



func GenerateServerKey()[]byte{
	xs := RandomZ()
	return xs.Bytes()
}

// SystemInitialization Complete
func SystemInitialization(xx0 []byte){
	x0 = new(big.Int).SetBytes(xx0)
	X0 = new(Point).ScalarBaseMultInt(x0)
}

func ClientInfo(){
	n = RandomZ().Bytes()
	r = RandomZ().Bytes()
	k = RandomZ().Bytes()
	Pw = RandomZ().Bytes()
	numZero = big.NewInt(0).Bytes()
	numOne = big.NewInt(1).Bytes()
}

func EncryptionA()([]byte, []byte, []byte){
	// T0 = g^r
	T0 = new(Point).ScalarBaseMult(r)
	// T1 = g^rx0 * g^H(g^rx0) * g^H(pw, n, 0)
	grx0 := X0.ScalarMult(r)
	//Hgrx0 := sha1.Sum(grx0.Marshal())
	//Hgrx0_ := Hgrx0[:]
	Hgrx0_ := HashZ(grx0.Marshal())
	Hpwn0_ := HashZ(Pw, n, numZero)
	T1e := Gf.Add(Hgrx0_, new(big.Int).Set(Hpwn0_))
	T1 = grx0.Add(new(Point).ScalarBaseMultInt(T1e))

	Hpwn1_ := HashZ(Pw, n, numOne).Bytes()
	return Hpwn1_, r, k
}

func EncryptionB(TT2 []byte){
	T2, _ = PointUnmarshal(TT2)
}

func Decryption(pw0 []byte)([]byte, []byte){
	// C0 = T1 / g^(H(pw0, n, 0))
	hpwn0 := HashZ(pw0, n, numZero)
	denominator := new(Point).ScalarBaseMultInt(hpwn0).Neg()
	C0 := T1.Add(denominator)
	T0x0 := T0.ScalarMultInt(x0)
	//hT0x0 := sha1.Sum(T0x0.Marshal())
	//hT0x0_ := hT0x0[:]
	hT0x0_ := HashZ(T0x0.Marshal())

	// leftVal = T0^x0 * H(T0^x0)
	leftVal := T0x0.Add(new(Point).ScalarBaseMultInt(hT0x0_))
	var flag *big.Int
	if leftVal.Equal(C0) {
		flag = big.NewInt(1)
	} else {
		flag = big.NewInt(0)
	}
	return flag.Bytes(), T0.Marshal()
}

func Verifier(C0, C1, U, GX1R, X1 []byte) bool{
	c0 := new(big.Int).SetBytes(C0)
	c1 := new(big.Int).SetBytes(C1)
	u := new(big.Int).SetBytes(U)
	gx1r, _ := PointUnmarshal(GX1R)
	gx1,_ := PointUnmarshal(X1)

	cx0 := Gf.Mul(c0, x0)
	//cx1 := gf.Mul(c1, new(big.Int).SetBytes(x1))

	gx0r := X0.ScalarMult(r)

	t1e := Gf.Add(u, cx0)
	//t2e := gf.MulBytes(r, t1e)

	t1_ := gx1.ScalarMultInt(c1).Add(new(Point).ScalarBaseMultInt(t1e))
	t2_ := t1_.ScalarMult(r)

	c0_ := HashZ(X0.Marshal(), T0.Marshal(), gx0r.Marshal(), t1_.Marshal(), t2_.Marshal())
	c1_ := HashZ(gx1.Marshal(), T0.Marshal(), gx1r.Marshal(), t1_.Marshal(), t2_.Marshal())

	if c0.Cmp(c0_) != 0 {
		return false
	}
	if c1.Cmp(c1_) != 0 {
		return false
	}
	return true
}






