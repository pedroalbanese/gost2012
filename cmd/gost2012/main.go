// Command-line GOST R 34.10-2012 512-bit ParamSet:A VKO/Signer
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/pedroalbanese/gost2012"
)

var (
	derive = flag.Bool("derive", false, "Derive shared secret key.")
	keygen = flag.Bool("keygen", false, "Generate keypair.")
	key    = flag.String("key", "", "Private/Public key.")
	public = flag.String("pub", "", "Remote's side Public key.")
	sig    = flag.String("signature", "", "Signature.")
	sign   = flag.Bool("sign", false, "Sign with Private key.")
	verify = flag.Bool("verify", false, "Verify with Public key.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "GOST2012 Signer - ALBANESE Research Lab")
		fmt.Fprintln(os.Stderr, "GOST R 34.10-2012 512-bit ParamSet A\n")
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(2)
	}

	var privatekey *ecdsa.PrivateKey
	var pubkey ecdsa.PublicKey
	var pub *ecdsa.PublicKey
	var err error
	var pubkeyCurve elliptic.Curve

	pubkeyCurve = gost2012.TC26512A()

	if *keygen {
		if *key != "" {
			privatekey, err = ReadPrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			privatekey = new(ecdsa.PrivateKey)
			privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if len(WritePrivateKeyToHex(privatekey)) != 128 {
				log.Fatal("Private key too short!")
				os.Exit(1)
			}
		}
		pubkey = privatekey.PublicKey
		fmt.Println("Private= " + WritePrivateKeyToHex(privatekey))
		fmt.Println("Public= " + WritePublicKeyToHex(&pubkey))
		os.Exit(0)
	}

	if *derive {
		private, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := ReadPublicKeyFromHex(*public)
		if err != nil {
			log.Fatal(err)
		}

		b, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.Bytes())
		shared := sha256.Sum256(b.Bytes())
		fmt.Printf("Shared= %x\n", shared)
		os.Exit(0)
	}

	if *sign {
		var h hash.Hash
		h = sha256.New()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}

		privatekey, err = ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}

		signature, err := Sign(h.Sum(nil), privatekey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", signature)
		os.Exit(0)
	}

	if *verify {
		var h hash.Hash
		h = sha256.New()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}

		pub, err = ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}

		sig, _ := hex.DecodeString(*sig)

		verifystatus := Verify(h.Sum(nil), sig, pub)
		fmt.Println(verifystatus)
		if verifystatus {
			os.Exit(0)
		} else {
			os.Exit(1)
		}		
	}
}

func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}

func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	digest := sha256.Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

func ReadPrivateKeyFromHex(Dhex string) (*ecdsa.PrivateKey, error) {
	c := gost2012.TC26512A()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func WritePrivateKeyToHex(key *ecdsa.PrivateKey) string {
	d := key.D.Bytes()
	if n := len(d); n < 64 {
		d = append(zeroByteSlice()[:128-n], d...)
	}
	c := []byte{}
	c = append(c, d...)
	return hex.EncodeToString(c)
}

func ReadPublicKeyFromHex(Qhex string) (*ecdsa.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 129 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 128 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(ecdsa.PublicKey)
	pub.Curve = gost2012.TC26512A()
	pub.X = new(big.Int).SetBytes(q[:64])
	pub.Y = new(big.Int).SetBytes(q[64:])
	return pub, nil
}

func WritePublicKeyToHex(key *ecdsa.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if n := len(x); n < 64 {
		x = append(zeroByteSlice()[:64-n], x...)
	}
	if n := len(y); n < 64 {
		y = append(zeroByteSlice()[:64-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	return hex.EncodeToString(c)
}

func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}
