package client

import (
	. "18phe/utils"
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

	c1 := T1.Add(new(Point).ScalarBaseMult(u))
	mid := new(Point).ScalarBaseMultInt(HashZ(un, pw, nc)).ScalarMult(kc)
	c2 := T2.Add(h.ScalarMult(u)).Add(mid.Neg())
	c3 := T3.Add(z.ScalarMult(u))
	return c1.Marshal(), c2.Marshal(), c3.Marshal()
}
