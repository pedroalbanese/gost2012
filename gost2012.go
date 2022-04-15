// Parameters for the GOST R 34.10-2012 512-bit Elliptic curves
package gost2012

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once
var tc26512a *elliptic.CurveParams
var tc26512b *elliptic.CurveParams

func initTC26512A() {
	tc26512a = new(elliptic.CurveParams)
	tc26512a.P, _ = new(big.Int).SetString("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", 16)
	tc26512a.N, _ = new(big.Int).SetString("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", 16)
	tc26512a.B, _ = new(big.Int).SetString("00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", 16)
	tc26512a.Gx, _ = new(big.Int).SetString("03", 16)
	tc26512a.Gy, _ = new(big.Int).SetString("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4", 16)
	tc26512a.BitSize = 512
}

func TC26512A() elliptic.Curve {
	initonce.Do(initTC26512A)
	return tc26512a
}

func initTC26512B() {
	tc26512b = new(elliptic.CurveParams)
	tc26512b.P, _ = new(big.Int).SetString("008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F", 16)
	tc26512b.N, _ = new(big.Int).SetString("00800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD", 16)
	tc26512b.B, _ = new(big.Int).SetString("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116", 16)
	tc26512b.Gx, _ = new(big.Int).SetString("02", 16)
	tc26512b.Gy, _ = new(big.Int).SetString("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD", 16)
	tc26512b.BitSize = 512
}

func TC26512B() elliptic.Curve {
	initonce.Do(initTC26512B)
	return tc26512b
}
