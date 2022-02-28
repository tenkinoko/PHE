package client

import (
	. "18phe/utils"
	"math/big"
)

var (
	// client-generated variations at initialization
	sk *big.Int
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

	// from server
	h *Point
	z *Point
	hs *Point
	ns []byte
	ks []byte

)

// Init Phase
func Init() {
	un = RandomZ().Bytes()
	r = RandomZ().Bytes()
	kc = RandomZ().Bytes()
	pw = RandomZ().Bytes()
}

// KGenC at Setup Phase
func KGenC() []byte {
	return RandomZ().Bytes()
}

// Enrollment phase
func Enrollment() {
	hc = new(Point).ScalarBaseMultInt(HashZ(un, nc)).ScalarBaseMult(kc)
	zr = z.ScalarMult(r)
	gr = new(Point).ScalarBaseMult(r)
}

// Validation Phase
func Validation(){
	T1 = gr
	T2 = h.ScalarMult(r).Add(hs).Add(hc)
	T3 = zr

	u = RandomZ().Bytes()

	c1 := T1.Add(new(Point).ScalarMult(r))
	c2 := T2.Add(h.ScalarMult(u)).Add(new(Point).ScalarBaseMultInt(HashZ(un, pw, nc)).ScalarMult(kc).Neg())
	c3 := T3.Add(z.ScalarMult(u))

}