package phe

import (
	"math/big"

	"github.com/golang/protobuf/proto"
	//"math/big"
)

var (
	x_0 *big.Int
	x_1 *big.Int
	X_0 *Point
	X_1 *Point
)

// Negotiation between Server and Key Server At the very beginning
func Negotiation(respBytes []byte) ([]byte, error) {
	resp := &NegotiationBegin{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return nil, err
	}
	xs := resp.Xs
	xks := randomZ()
	x_0 = hashZ(xs, xks.Bytes(), big.NewInt(0).Bytes())
	x_1 = hashZ(xs, xks.Bytes(), big.NewInt(1).Bytes())
	X_0 = new(Point).ScalarBaseMultInt(x_0)
	X_1 = new(Point).ScalarBaseMultInt(x_1)
	return proto.Marshal(&NegotiationResponse{
		X0: x_0.Bytes(),
	})
}

func ThirdPartGeneration(respBytes []byte) ([]byte, error) {
	resp := &T2Generation{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return nil, err
	}
	Hpwn1_ := resp.E1
	r := resp.E2
	k := resp.E3
	T2e := gf.Add(gf.MulBytes(r, x_1), gf.AddBytes(k, new(big.Int).SetBytes(Hpwn1_)))
	T2 := new(Point).ScalarBaseMultInt(T2e)
	return proto.Marshal(&T2Response{
		T2: T2.Marshal(),
	})
}

func ZKProof(respBytes []byte) ([]byte, error) {
	resp := &ProofOfX{}
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return nil, err
	}
	T0 := resp.TT0
	FlagMsg := resp.Flag
	Flag := new(big.Int).SetBytes(FlagMsg)
	if Flag.Cmp(big.NewInt(1)) == 0 {
		return ProverOfSuccess(T0)

	} else {
		return nil, nil
	}

}

func ProverOfSuccess(t0 []byte) ([]byte, error) {
	gr, _ := PointUnmarshal(t0)
	v := randomZ().Bytes()
	t1 := new(Point).ScalarBaseMult(v)
	t2 := gr.ScalarMult(v)

	gx0r := gr.ScalarMultInt(x_0)
	gx1r := gr.ScalarMultInt(x_1)

	c0 := hashZ(X_0.Marshal(), T0.Marshal(), gx0r.Marshal(), t1.Marshal(), t2.Marshal())
	c1 := hashZ(X_1.Marshal(), T0.Marshal(), gx1r.Marshal(), t1.Marshal(), t2.Marshal())

	cx0 := gf.Mul(c0, x_0)
	cx1 := gf.Mul(c1, x_1)

	cx0neg := gf.Neg(cx0)
	cx1neg := gf.Neg(cx1)

	u := gf.AddBytes(v, gf.Add(cx0neg, cx1neg))

	// + gx1r -> server
	return proto.Marshal(&ProverResponse{
		C0:   c0.Bytes(),
		C1:   c1.Bytes(),
		U:    u.Bytes(),
		GX1R: gx1r.Marshal(),
		X1:   X_1.Marshal(),
	})
}
