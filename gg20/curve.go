package gg20

import (
	"crypto/elliptic"
	"errors"

	secp256k1 "github.com/btcsuite/btcd/btcec"
)

var (
	ec elliptic.Curve
)

func init() {
	ec = secp256k1.S256()
}

func EC() elliptic.Curve {
	return ec
}

func SetCurve(curve elliptic.Curve) {
	if curve == nil {
		panic(errors.New("SetCurve received a nil curve"))
	}
	ec = curve
}
