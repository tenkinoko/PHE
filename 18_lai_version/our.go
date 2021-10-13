package phe

import (
	"crypto/sha1"
	"math/big"
)

var (
	n []byte
	r []byte
	k []byte
	x0 []byte // sk_s
	x1 []byte // sk_ks
	pw []byte
	v []byte
	T0 *Point
	T1 *Point
	T2 *Point
)

func enrolling(){
	n = randomZ().Bytes()
	r = randomZ().Bytes()
	k = randomZ().Bytes()
	x0 = randomZ().Bytes() // sk_s
	x1 = randomZ().Bytes() // sk_ks
	pw = randomZ().Bytes()

	v = randomZ().Bytes()
}

func encryption() {
	// T0 = g^r
	T0 = new(Point).ScalarBaseMult(r)
	// T1 = g^rx0 * g^H(g^rx0) * g^H(pw, n, 0)
	gr := new(Point).ScalarBaseMult(r)
	grx0 := gr.ScalarMult(x0)
	Hgrx0 := sha1.Sum(grx0.Marshal())
	Hgrx0_ := Hgrx0[:]
	Hpwn0_ := HashPwd(pw, n, 0)
	T1e := gf.Add(gf.MulBytes(r, new(big.Int).SetBytes(x0)), gf.AddBytes(Hgrx0_, new(big.Int).SetBytes(Hpwn0_)))
	T1 = new(Point).ScalarBaseMultInt(T1e)
	//T1 = grx0.Add(new(Point).ScalarBaseMult(Hpwn0_)).Add(new(Point).ScalarBaseMult(Hgrx0_))
	// T2 = g^rx1 * g^H(pw, n, 1) * g^k
	//grx1 := gr.ScalarMult(x1)
	Hpwn1_ := HashPwd(pw, n, 1)
	T2e := gf.Add(gf.MulBytes(r, new(big.Int).SetBytes(x1)), gf.AddBytes(k, new(big.Int).SetBytes(Hpwn1_)))
	//T2 = grx1.Add(new(Point).ScalarBaseMult(Hpwn1_)).Add(new(Point).ScalarBaseMult(k))
	T2 = new(Point).ScalarBaseMultInt(T2e)

}

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

func proofOfSuccess() bool{
	t1 := new(Point).ScalarBaseMult(v)
	t2 := new(Point).ScalarBaseMult(r).ScalarMult(v)

	g := new(Point).ScalarBaseMultInt(big.NewInt(1))
	gx0 := new(Point).ScalarBaseMult(x0)
	gx1 := new(Point).ScalarBaseMult(x1)
	gr := new(Point).ScalarBaseMult(r)
	gx0r := gx0.ScalarMult(r)
	gx1r := gx1.ScalarMult(r)
	c0 := hashZ(g.Marshal(), gx0.Marshal(), gr.Marshal(), gx0r.Marshal(), t1.Marshal(), t2.Marshal())

	c1 := hashZ(g.Marshal(), gx1.Marshal(), gr.Marshal(), gx1r.Marshal(), t1.Marshal(), t2.Marshal())

	cx0 := gf.Mul(c0, new(big.Int).SetBytes(x0))
	cx1 := gf.Mul(c1, new(big.Int).SetBytes(x1))
	cx0neg := gf.Neg(cx0)
	cx1neg := gf.Neg(cx1)

	u := gf.AddBytes(v, gf.Add(cx0neg, cx1neg))


	t1e := gf.Add(u, gf.Add(cx0, cx1))
	t2e := gf.MulBytes(r, t1e)

	t1_ := new(Point).ScalarBaseMultInt(t1e)
	t2_ := new(Point).ScalarBaseMultInt(t2e)
	//t1_ := new(Point).ScalarBaseMultInt(u).Add(new(Point).ScalarBaseMult(x0).ScalarMultInt(c0)).Add(new(Point).ScalarBaseMult(x1).ScalarMultInt(c1))
	//t2_ := new(Point).ScalarBaseMult(r).ScalarMultInt(u).Add(new(Point).ScalarBaseMult(x0).ScalarMult(r).ScalarMultInt(c0)).
	//	Add(new(Point).ScalarBaseMult(x1).ScalarMult(r).ScalarMultInt(c1))



	c0_ := hashZ(g.Marshal(), gx0.Marshal(), gr.Marshal(), gx0r.Marshal(), t1_.Marshal(), t2_.Marshal())
	c1_ := hashZ(g.Marshal(), gx1.Marshal(), gr.Marshal(), gx1r.Marshal(), t1_.Marshal(), t2_.Marshal())

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
	enrolling()
	encryption()
	res := decryption(pw)
	if res {
		proofOfSuccess()
	} else {
		proofOfFailure()
	}
}