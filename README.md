# GOST2012
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/gost2012/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/gost2012?status.png)](http://godoc.org/github.com/pedroalbanese/gost2012)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/gost2012)](https://goreportcard.com/report/github.com/pedroalbanese/gost2012)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/gost2012)](https://github.com/pedroalbanese/gost2012/releases)

### GOST R 34.10-2012 512-bit curve ParamSet A and B
Package implements the elliptic curves originally described in RFC 7836

## Usage
```
Usage of gost2012:
  -dec
        Decrypt with Private key
  -derive
        Derive shared secret key
  -enc
        Encrypt with Public key
  -key string
        Private/Public key
  -keygen
        Generate keypair
  -pub string
        Remote's side Public key
  -sign
        Sign with Private key
  -signature string
        Signature
  -verify
        Verify with Public key
```
## Examples
#### Asymmetric keypair generation:
```sh
./gost2012 -keygen 
```
#### Digital signature (ECDSA):
```sh
./gost2012 -sign -key $prvkey < file.ext > sign.txt
sign=$(cat sign.txt)
./gost2012 -verify -key $pubkey -signature $sign < file.ext
```
#### Asymmetric Encryption:
```sh
./gost2012 -enc -key $pubkey < file.ext > file.enc
./gost2012 -dec -key $prvkey < file.enc
```
#### Shared key agreement (ECDH a.k.a. VKO):
```sh
./gost2012 -derive -key $prvkey -pub $pubkey
```

## License

This project is licensed under the ISC License.

##### Military-Grade Reliability. Copyright (c) 2020-2022 ALBANESE Research Lab.
