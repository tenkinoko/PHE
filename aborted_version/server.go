package main

import (
	"crypto/sha1"
	"fmt"
)

var (
	n = Random256()
	r = Random256()
	k = Random256()
	x0 = Random256() // sk_s
	x1 = Random256() // sk_ks
	pw = Random256()

	v = Random256()
	n0 = Random256()
	n1 = Random256()

	T0 *Point
	T1 *Point
	T2 *Point
)

func encryption() {
	// T0 = g^r
	T0 = new(Point).ScalarBaseMult(r)
	// T1 = g^rx0 * g^H(g^rx0) * g^H(pw, n, 0)
	gr := new(Point).ScalarBaseMult(r)
	grx0 := gr.ScalarMult(x0)
	Hgrx0 := sha1.Sum(grx0.Marshal())
	Hgrx0_ := Hgrx0[:]
	Hpwn0_ := HashPwd(pw, n, 0)
	T1 = grx0.Add(new(Point).ScalarBaseMult(Hpwn0_)).Add(new(Point).ScalarBaseMult(Hgrx0_))
	// T2 = g^rx1 * g^H(pw, n, 1) * g^k
	grx1 := gr.ScalarMult(x1)
	Hpwn1_ := HashPwd(pw, n, 1)
	T2 = grx1.Add(new(Point).ScalarBaseMult(Hpwn1_)).Add(new(Point).ScalarBaseMult(k))

}

func decryption(pw0 []byte){
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
		fmt.Println(proofOfSuccess())
	} else {
		proofOfFailure()
	}

}

func proofOfSuccess() bool{
	t1 := new(Point).ScalarBaseMult(n0).ScalarMult(x0).ScalarMult(v)
	t2 := new(Point).ScalarBaseMult(n1).ScalarMult(x0).ScalarMult(v)
	t3 := new(Point).ScalarBaseMult(v)

	str1 := []byte("1")
	//c_ := [][]byte{str1, new(Point).ScalarBaseMult(x1).Marshal(), new(Point).ScalarBaseMult(x1).ScalarMult(n0).Marshal(),
	//	new(Point).ScalarBaseMult(x1).ScalarMult(n1).Marshal(), t1.Marshal(), t2.Marshal(), t3.Marshal()}
	//c := bytes.Join(c_, []byte{})

	c := hashZ(str1, new(Point).ScalarBaseMult(x1).Marshal(), new(Point).ScalarBaseMult(x1).ScalarMult(n0).Marshal(),
		new(Point).ScalarBaseMult(x1).ScalarMult(n1).Marshal(), t1.Marshal(), t2.Marshal(), t3.Marshal())
	// u = v + x*c
	u := gf.AddBytes(v, gf.MulBytes(x1, c)).Bytes()
	u_ := padZ(u)
	gu := new(Point).ScalarBaseMult(v).Add(new(Point).ScalarBaseMult(x1).ScalarMultInt(c))

	g_u:= new(Point).ScalarBaseMult(u_)
	//u := gf.MulBytes(x1, new(big.Int).SetBytes(c)).Bytes()
	//gu := new(Point).ScalarBaseMult(x1).ScalarMult(c)
	//g_u := new(Point).ScalarBaseMult(u)
	fmt.Println(gu.Equal(g_u))
	//c_ks := c

	term1_l := t1.Add(new(Point).ScalarBaseMult(n0).ScalarMult(x1).ScalarMultInt(c).ScalarMult(x0))
	term1_r := new(Point).ScalarBaseMult(u_).ScalarMult(n0).ScalarMult(x0)
	term2_l := t2.Add(new(Point).ScalarBaseMult(n1).ScalarMult(x1).ScalarMultInt(c).ScalarMult(x0))
	term2_r := new(Point).ScalarBaseMult(u_).ScalarMult(n1).ScalarMult(x0)
	term3_l := t3.Add(new(Point).ScalarBaseMult(x1).ScalarMultInt(c))
	term3_r := new(Point).ScalarBaseMult(u_)

	if !term1_l.Equal(term1_r) {
		return false
	}
	if !term2_l.Equal(term2_r) {
		return false
	}
	if !term3_l.Equal(term3_r) {
		return false
	}
	return true
}

func proofOfFailure(){}

func main(){
	encryption()
	decryption(pw)
}