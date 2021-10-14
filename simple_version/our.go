package phe

import (
	"crypto/sha1"
	"math/big"
)

var (
	n []byte
	r []byte
	k []byte
	x0 []byte // sk_s 不存
	X0 *Point
	x1 []byte // sk_ks
	X1 *Point
	pw []byte
	T0 *Point
	T1 *Point
	T2 *Point
)


// Server + Key Server(最初始的方案）
func initialize(){
	x0 = randomZ().Bytes() // sk_s
	X0 = new(Point).ScalarBaseMult(x0)
	x1 = randomZ().Bytes() // sk_ks
	X1 = new(Point).ScalarBaseMult(x1)
}

// Client
func enrolling(){
	n = randomZ().Bytes()
	r = randomZ().Bytes()
	k = randomZ().Bytes()
	pw = randomZ().Bytes()
}

// Server
func encryption() {
	// T0 = g^r
	T0 = new(Point).ScalarBaseMult(r)
	// T1 = g^rx0 * g^H(g^rx0) * g^H(pw, n, 0)
	grx0 := X0.ScalarMult(r)
	Hgrx0 := sha1.Sum(grx0.Marshal())
	Hgrx0_ := Hgrx0[:]
	Hpwn0_ := HashPwd(pw, n, 0)
	T1e := gf.AddBytes(Hgrx0_, new(big.Int).SetBytes(Hpwn0_))
	T1 = grx0.Add(new(Point).ScalarBaseMultInt(T1e))

	//T2 = grx1.Add(new(Point).ScalarBaseMult(Hpwn1_)).Add(new(Point).ScalarBaseMult(k))
	Hpwn1_ := HashPwd(pw, n, 1)
	T2e := gf.Add(gf.MulBytes(r, new(big.Int).SetBytes(x1)), gf.AddBytes(k, new(big.Int).SetBytes(Hpwn1_)))
	T2 = new(Point).ScalarBaseMultInt(T2e)

}

// Key Server
func decryption(pw0 []byte) bool{
	// C0 = T1 / g^(H(pw0, n, 0))
	hpwn0 := HashPwd(pw0, n, 0)
	denominator := new(Point).ScalarBaseMult(hpwn0).Neg()
	C0 := T1.Add(denominator)
	T0x0 := T0.ScalarMult(x0)
	hT0x0 := sha1.Sum(T0x0.Marshal())
	hT0x0_ := hT0x0[:]

	// leftVal = T0^x0 * H(T0^x0)
	leftVal := T0x0.Add(new(Point).ScalarBaseMult(hT0x0_))
	if leftVal.Equal(C0) {
		return true
	} else {
		return false
	}
}

// key server
func proofOfSuccess() (*big.Int, *big.Int, *big.Int, *Point) {
	v := randomZ().Bytes()
	t1 := new(Point).ScalarBaseMult(v)
	t2 := new(Point).ScalarBaseMult(r).ScalarMult(v)

	gx0r := X0.ScalarMult(r)
	gx1r := X1.ScalarMult(r)

	c0 := hashZ(X0.Marshal(), T0.Marshal(), gx0r.Marshal(), t1.Marshal(), t2.Marshal())
	c1 := hashZ(X1.Marshal(), T0.Marshal(), gx1r.Marshal(), t1.Marshal(), t2.Marshal())

	cx0 := gf.Mul(c0, new(big.Int).SetBytes(x0))
	cx1 := gf.Mul(c1, new(big.Int).SetBytes(x1))

	cx0neg := gf.Neg(cx0)
	cx1neg := gf.Neg(cx1)

	u := gf.AddBytes(v, gf.Add(cx0neg, cx1neg))

	// + gx1r -> server
	return c0, c1, u, gx1r
}

// server
func verifierOfSuccess(c0, c1, u *big.Int, gx1r *Point)(bool){
	cx0 := gf.Mul(c0, new(big.Int).SetBytes(x0))
	cx1 := gf.Mul(c1, new(big.Int).SetBytes(x1))

	gx0r := X0.ScalarMult(r)

	t1e := gf.Add(u, gf.Add(cx0, cx1))
	t2e := gf.MulBytes(r, t1e)

	t1_ := new(Point).ScalarBaseMultInt(t1e)
	t2_ := new(Point).ScalarBaseMultInt(t2e)

	c0_ := hashZ(X0.Marshal(), T0.Marshal(), gx0r.Marshal(), t1_.Marshal(), t2_.Marshal())
	c1_ := hashZ(X1.Marshal(), T0.Marshal(), gx1r.Marshal(), t1_.Marshal(), t2_.Marshal())

	if c0.Cmp(c0_) != 0 {
		return false
	}
	if c1.Cmp(c1_) != 0 {
		return false
	}
	return true
}



func proofOfFailure(){}

func main(){
	initialize()
	enrolling()
	encryption()
	res := decryption(pw)
	if res {
		proofOfSuccess()
	} else {
		proofOfFailure()
	}
}