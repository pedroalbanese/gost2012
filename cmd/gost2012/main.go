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
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"os"
	"sync"

	"github.com/pedroalbanese/gogost/gost34112012512"
	"github.com/pedroalbanese/randomart"
)

var (
	dec    = flag.Bool("dec", false, "Decrypt with EC-GOST2012 Privatekey.")
	derive = flag.Bool("derive", false, "Derive shared secret key.")
	enc    = flag.Bool("enc", false, "Encrypt with EC-GOST2012 Publickey.")
	key    = flag.String("key", "", "Private/Public key.")
	keygen = flag.Bool("keygen", false, "Generate keypair.")
	public = flag.String("pub", "", "Remote's side Public key.")
	sig    = flag.String("signature", "", "Signature.")
	sign   = flag.Bool("sign", false, "Sign with Private key.")
	verify = flag.Bool("verify", false, "Verify with Public key.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "GOST Signer - ALBANESE Research Lab")
		fmt.Fprintln(os.Stderr, "GOST R 34.10-2012 512-bit ParamSetA\n")
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(2)
	}

	var privatekey *ecdsa.PrivateKey
	var pubkey ecdsa.PublicKey
	var pub *ecdsa.PublicKey
	var err error
	var pubkeyCurve elliptic.Curve

	pubkeyCurve = GOST2012()

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
			for len(WritePrivateKeyToHex(privatekey)) != 128 {
				privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				break
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

		Sum256 := func(msg []byte) []byte {
			res := gost34112012512.New()
			res.Write(msg)
			hash := res.Sum(nil)
			return []byte(hash)
		}

		shared := Sum256(b.Bytes())
		fmt.Printf("Shared= %x\n", shared)
		os.Exit(0)
	}

	if *sign {
		var h hash.Hash
		h = gost34112012512.New()

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
		h = gost34112012512.New()

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
		os.Exit(0)
	}

	if *enc {
		pub2, err := ReadPublicKeyFromHexX(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := EncryptAsn1(pub2, []byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", ciphertxt)
		os.Exit(0)
	}

	if *dec {
		private, err := ReadPrivateKeyFromHexX(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str, _ := hex.DecodeString(string(scanner))
		plaintxt, err := DecryptAsn1(private, []byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", plaintxt)
		os.Exit(0)
	}

	if *key == "-" {
		fmt.Println(randomart.FromFile(os.Stdin))
	} else {
		fmt.Println(randomart.FromString(*key))
	}
}

func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {

	Sum256 := func(msg []byte) []byte {
		res := gost34112012512.New()
		res.Write(msg)
		hash := res.Sum(nil)
		return []byte(hash)
	}

	digest := Sum256(data)

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

	Sum256 := func(msg []byte) []byte {
		res := gost34112012512.New()
		res.Write(msg)
		hash := res.Sum(nil)
		return []byte(hash)
	}

	digest := Sum256(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

func ReadPrivateKeyFromHex(Dhex string) (*ecdsa.PrivateKey, error) {
	c := GOST2012()
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

func ReadPrivateKeyFromHexX(Dhex string) (*PrivateKey, error) {
	c := GOST2012()
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
	priv := new(PrivateKey)
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
	pub.Curve = GOST2012()
	pub.X = new(big.Int).SetBytes(q[:64])
	pub.Y = new(big.Int).SetBytes(q[64:])
	return pub, nil
}

func ReadPublicKeyFromHexX(Qhex string) (*PublicKey, error) {
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
	pub := new(PublicKey)
	pub.Curve = GOST2012()
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
	c = append([]byte{0x04}, c...)
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

var initonce sync.Once
var gost2012 *elliptic.CurveParams

func initGOST2012() {
	gost2012 = new(elliptic.CurveParams)
	gost2012.P, _ = new(big.Int).SetString("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", 16)
	gost2012.N, _ = new(big.Int).SetString("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", 16)
	gost2012.B, _ = new(big.Int).SetString("00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", 16)
	gost2012.Gx, _ = new(big.Int).SetString("03", 16)
	gost2012.Gy, _ = new(big.Int).SetString("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4", 16)
	gost2012.BitSize = 512
}

func GOST2012() elliptic.Curve {
	initonce.Do(initGOST2012)
	return gost2012
}

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type gost2012Cipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

func (pub *PublicKey) EncryptAsn1(data []byte, random io.Reader) ([]byte, error) {
	return EncryptAsn1(pub, data, random)
}

func (priv *PrivateKey) DecryptAsn1(data []byte) ([]byte, error) {
	return DecryptAsn1(priv, data)
}

func EncryptAsn1(pub *PublicKey, data []byte, rand io.Reader) ([]byte, error) {
	cipher, err := Encrypt(pub, data, rand, 0)
	if err != nil {
		return nil, err
	}
	return CipherMarshal(cipher)
}

func DecryptAsn1(pub *PrivateKey, data []byte) ([]byte, error) {
	cipher, err := CipherUnmarshal(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(pub, cipher, 0)
}

func CipherMarshal(data []byte) ([]byte, error) {
	data = data[1:]
	x := new(big.Int).SetBytes(data[:64])
	y := new(big.Int).SetBytes(data[64:128])
	hash := data[128:192]
	cipherText := data[192:]
	return asn1.Marshal(gost2012Cipher{x, y, hash, cipherText})
}

func CipherUnmarshal(data []byte) ([]byte, error) {
	var cipher gost2012Cipher
	_, err := asn1.Unmarshal(data, &cipher)
	if err != nil {
		return nil, err
	}
	x := cipher.XCoordinate.Bytes()
	y := cipher.YCoordinate.Bytes()
	hash := cipher.HASH
	if err != nil {
		return nil, err
	}
	cipherText := cipher.CipherText
	if err != nil {
		return nil, err
	}
	if n := len(x); n < 64 {
		x = append(zeroByteSlice()[:64-n], x...)
	}
	if n := len(y); n < 64 {
		y = append(zeroByteSlice()[:64-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	c = append(c, hash...)
	c = append(c, cipherText...)
	return append([]byte{0x04}, c...), nil
}

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

func Encrypt(pub *PublicKey, data []byte, random io.Reader, mode int) ([]byte, error) {
	length := len(data)
	for {
		c := []byte{}
		curve := pub.Curve
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		if n := len(x1Buf); n < 64 {
			x1Buf = append(zeroByteSlice()[:64-n], x1Buf...)
		}
		if n := len(y1Buf); n < 64 {
			y1Buf = append(zeroByteSlice()[:64-n], y1Buf...)
		}
		if n := len(x2Buf); n < 64 {
			x2Buf = append(zeroByteSlice()[:64-n], x2Buf...)
		}
		if n := len(y2Buf); n < 64 {
			y2Buf = append(zeroByteSlice()[:64-n], y2Buf...)
		}
		c = append(c, x1Buf...)
		c = append(c, y1Buf...)
		tm := []byte{}
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)

		Sum256 := func(msg []byte) []byte {
			res := gost34112012512.New()
			res.Write(msg)
			hash := res.Sum(nil)
			return []byte(hash)
		}

		h := Sum256(tm)
		c = append(c, h...)
		ct, ok := kdf(length, x2Buf, y2Buf)
		if !ok {
			continue
		}
		c = append(c, ct...)
		for i := 0; i < length; i++ {
			c[192+i] ^= data[i]
		}
		switch mode {

		case 0:
			return append([]byte{0x04}, c...), nil
		case 1:
			c1 := make([]byte, 128)
			c2 := make([]byte, len(c)-192)
			c3 := make([]byte, 64)
			copy(c1, c[:128])
			copy(c3, c[128:192])
			copy(c2, c[192:])
			ciphertext := []byte{}
			ciphertext = append(ciphertext, c1...)
			ciphertext = append(ciphertext, c2...)
			ciphertext = append(ciphertext, c3...)
			return append([]byte{0x04}, ciphertext...), nil
		default:
			return append([]byte{0x04}, c...), nil
		}
	}
}

func Decrypt(priv *PrivateKey, data []byte, mode int) ([]byte, error) {
	switch mode {
	case 0:
		data = data[1:]
	case 1:
		data = data[1:]
		c1 := make([]byte, 128)
		c2 := make([]byte, len(data)-192)
		c3 := make([]byte, 64)
		copy(c2, data[128:len(data)-64])
		copy(c3, data[len(data)-64:])
		c := []byte{}
		c = append(c, c1...)
		c = append(c, c3...)
		c = append(c, c2...)
		data = c
	default:
		data = data[1:]
	}
	length := len(data) - 192
	curve := priv.Curve
	x := new(big.Int).SetBytes(data[:64])
	y := new(big.Int).SetBytes(data[64:128])
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 64 {
		x2Buf = append(zeroByteSlice()[:64-n], x2Buf...)
	}
	if n := len(y2Buf); n < 64 {
		y2Buf = append(zeroByteSlice()[:64-n], y2Buf...)
	}
	c, ok := kdf(length, x2Buf, y2Buf)
	if !ok {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	for i := 0; i < length; i++ {
		c[i] ^= data[i+192]
	}
	tm := []byte{}
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)

	Sum256 := func(msg []byte) []byte {
		res := gost34112012512.New()
		res.Write(msg)
		hash := res.Sum(nil)
		return []byte(hash)
	}

	h := Sum256(tm)
	if bytes.Compare(h, data[128:192]) != 0 {
		return c, errors.New("Decrypt: failed to decrypt")
	}
	return c, nil
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(length int, x ...[]byte) ([]byte, bool) {
	var c []byte

	ct := 1
	h := gost34112012512.New()
	for i, j := 0, (length+65)/64; i < j; i++ {
		h.Reset()
		for _, xx := range x {
			h.Write(xx)
		}
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%64 != 0 {
			c = append(c, hash[:length%64]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

