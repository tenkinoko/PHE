package main

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// Point represents an elliptic curve point
type Point struct {
	X, Y *big.Int
}

var (
	pn   = curve.Params().P
	zero = big.NewInt(0)
)

// PointUnmarshal validates & converts byte array to an elliptic curve point object
func PointUnmarshal(data []byte) (*Point, error) {
	if len(data) != 65 {
		return nil, errors.New("Invalid curve point")
	}
	x, y := elliptic.Unmarshal(curve, data)
	if x == nil || y == nil {
		return nil, errors.New("Invalid curve point")
	}
	return &Point{
		X: x,
		Y: y,
	}, nil
}

// Add adds two points
func (p *Point) Add(a *Point) *Point {
	x, y := curve.Add(p.X, p.Y, a.X, a.Y)
	return &Point{x, y}
}

// Neg inverts point's Y coordinate
func (p *Point) Neg() *Point {
	t := new(Point)
	t.X = p.X
	t.Y = new(big.Int).Sub(pn, p.Y)
	return t
}

// ScalarMult multiplies point to a number
func (p *Point) ScalarMult(b []byte) *Point {
	x, y := curve.ScalarMult(p.X, p.Y, b)

	return &Point{x, y}
}

// ScalarMultInt multiplies point to a number
func (p *Point) ScalarMultInt(b *big.Int) *Point {
	x, y := curve.ScalarMult(p.X, p.Y, b.Bytes())

	return &Point{x, y}
}

// ScalarBaseMult multiplies base point to a number
func (p *Point) ScalarBaseMult(b []byte) *Point {
	x, y := curve.ScalarBaseMult(b)

	return &Point{x, y}
}

// ScalarBaseMultInt multiplies base point to a number
func (p *Point) ScalarBaseMultInt(b *big.Int) *Point {
	x, y := curve.ScalarBaseMult(b.Bytes())

	return &Point{x, y}
}

// Marshal converts point to an array of bytes
func (p *Point) Marshal() []byte {

	if p.X.Cmp(zero) != 0 &&
		p.Y.Cmp(zero) != 0 {
		return elliptic.Marshal(curve, p.X, p.Y)
	}
	panic("zero point")
}

// Equal checks two points for equality
func (p *Point) Equal(other *Point) bool {
	return p.X.Cmp(other.X) == 0 &&
		p.Y.Cmp(other.Y) == 0
}
