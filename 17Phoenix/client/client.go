package client

import (
	. "18phe/utils"
	"math/big"
)

var (
	// client-generated variations at setup phase
	un []byte
	nc []byte
	r []byte
	kc []byte

	pw []byte

	// client-stored variations after enrollment phase
	hc *Point
	zr *Point
	gr *Point
	T1 *Point
	T2 *Point
	T3 *Point

	// client-generated variations at validation phase
	u []byte
	c1 *Point
	c2 *Point
	c3 *Point
)

func SetupClient() {
	un = RandomZ().Bytes()
	nc = RandomZ().Bytes()
	r = RandomZ().Bytes()
	kc = RandomZ().Bytes()
	pw = RandomZ().Bytes()
}


func EnrollmentClient(z_ []byte) []byte {
	z, _ := PointUnmarshal(z_)
	hc = new(Point).ScalarBaseMultInt(HashZ(un, pw, nc)).ScalarMult(kc)
	zr = z.ScalarMult(r)
	gr = new(Point).ScalarBaseMult(r)
	return un
}

func ValidationClient(hs_ []byte, ns_ []byte, h_ []byte, z_ []byte)([]byte, []byte, []byte){
	hs, _ := PointUnmarshal(hs_)
	h, _ := PointUnmarshal(h_)
	z, _ := PointUnmarshal(z_)
	T1 = gr
	T2 = h.ScalarMult(r).Add(hs).Add(hc)
	T3 = zr

	u = RandomZ().Bytes()

	c1 = T1.Add(new(Point).ScalarBaseMult(u))
	mid := new(Point).ScalarBaseMultInt(HashZ(un, pw, nc)).ScalarMult(kc)
	c2 = T2.Add(h.ScalarMult(u)).Add(mid.Neg())
	c3 = T3.Add(z.ScalarMult(u))
	return c1.Marshal(), c2.Marshal(), c3.Marshal()
}

func ZKProof(_h_ []byte, _c1_ []byte, _gS_ []byte, _s []byte, _kS []byte, h_ []byte, ns_ []byte) bool{
	_h, _ := PointUnmarshal(_h_)
	_c1, _ := PointUnmarshal(_c1_)
	_gS, _ := PointUnmarshal(_gS_)
	h, _ := PointUnmarshal(h_)
	numOne := big.NewInt(1).Bytes()
	g := new(Point).ScalarBaseMult(numOne)
	gS := new(Point).ScalarBaseMult(HashZ(un, ns_).Bytes())
	c := HashZ(g.Marshal(), h.Marshal(), c1.Marshal(), c2.Marshal(), gS.Marshal(), _h.Marshal(), _c1.Marshal(), _gS.Marshal())
	b11 := c1.ScalarMult(_s).Add(gS.ScalarBaseMult(_kS))
	b12 := _c1.Add(_gS).Add(c2.ScalarMultInt(c))
	b21 := new(Point).ScalarBaseMult(_s)
	b22 := _h.Add(h.ScalarMultInt(c))
	b11v := new(big.Int).SetBytes(b11.Marshal())
	b12v := new(big.Int).SetBytes(b12.Marshal())
	b21v := new(big.Int).SetBytes(b21.Marshal())
	b22v := new(big.Int).SetBytes(b22.Marshal())
	return b11v.Cmp(b12v) == 0 && b21v.Cmp(b22v) == 0
}

func Update(a , b, g, ze, h_, z_, hs_ []byte) {
	alpha := new(big.Int).SetBytes(a)
	beta := new(big.Int).SetBytes(b)
	gamma := new(big.Int).SetBytes(g)
	zeta := new(big.Int).SetBytes(ze)
	h, _ := PointUnmarshal(h_)
	z, _ := PointUnmarshal(z_)
	hs, _ := PointUnmarshal(hs_)

	kc_ := Gf.MulBytes(kc, alpha)
	v := RandomZ().Bytes()
	T1_ := T1.Add(new(Point).ScalarBaseMult(v))
	T2_ := ((T2.Add(h.ScalarMult(v))).ScalarMultInt(alpha)).Add((T1.Add(new(Point).ScalarBaseMult(v))).ScalarMultInt(beta)).Add(hs.ScalarMultInt(gamma))
	T3_ := ((T3.Add(z.ScalarMult(v))).ScalarMultInt(alpha)).Add((T1.Add(new(Point).ScalarBaseMult(v))).ScalarMultInt(zeta))
	kc = kc_.Bytes()
	T1 = T1_
	T2 = T2_
	T3 = T3_
}
