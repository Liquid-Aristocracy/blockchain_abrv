package main

import (
	"bytes"
	"encoding/binary"
	"encoding/base64"
	"log"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/rsa"
)

// IntToHex converts an int64 to a byte array
func IntToHex(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

// ReverseBytes reverses a byte array
func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}

func NewKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}

func VerifySignature(dataToVerify []byte, pubkey []byte) bool {
	curve := elliptic.P256()

	r := big.Int{}
	s := big.Int{}
	sigLen := len(tx.Sign)
	r.SetBytes(tx.Sign[:(sigLen / 2)])
	s.SetBytes(tx.Sign[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(pubkey)
	x.SetBytes(pubkey[:(keyLen / 2)])
	y.SetBytes(pubkey[(keyLen / 2):])

	rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	if ecdsa.Verify(&rawPubKey, []byte(dataToVerify), &r, &s) == false {
		return false
	}
	return true
}

func HashUpdateLog (histhash []byte, newlog [][]byte) []byte{
	hash := histhash
	for _, log := range newlog {
		datatohash := append(histhash, log)
		hash = sha256.Sum256(datatohash)
	}
	return hash
}

// RSA private encryption used in conversation encryption
func RsaPrivateEncrypt(plainText []byte, privKey *rsa.PrivateKey) []byte {
    ciphertext, err := rsa.SignPKCS1v15(nil, privKey, crypto.Hash(0), plainText)
    if err != nil {
        panic(fmt.Errorf("failed to encrypt: %w", err))
    }
    return ciphertext
}

// RSA public decryption used in conversation decryption
func RsaPublicDecrypt(cipherText []byte, pubKey *rsa.PublicKey) []byte {
    c := new(big.Int)
    m := new(big.Int)
    if err != nil {
        panic(fmt.Errorf("failed to encode base64: %w", err))
    }
    m.SetBytes(cipherText)
    e := big.NewInt(int64(pubKey.E))
    c.Exp(m, e, pubKey.N)
    out := c.Bytes()
    skip := 0
    for i := 2; i < len(out); i++ {
        if i+1 >= len(out) {
            break
        }
        if out[i] == 0xff && out[i+1] == 0 {
            skip = i + 2
            break
        }
    }
    return out[skip:]
}

func RsaPublicKeyToByte(pub *rsa.PublicKey) []byte {
    pubASN1, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
        panic(fmt.Errorf("failed to convert public key to string: %w", err))
    }

    pubBytes := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: pubASN1,
    })

    return pubBytes[:]
}

func RsaByteToPublicKey(pubByte []byte) *rsa.PublicKey {
    block, _ := pem.Decode(pubByte)
    enc := x509.IsEncryptedPEMBlock(block)
    b := block.Bytes
    if enc {
        b, err = x509.DecryptPEMBlock(block, nil)
        if err != nil {
            panic(fmt.Errorf("failed to convert string to public key: %w", err))
        }
    }
    ifc, err := x509.ParsePKIXPublicKey(b)
    if err != nil {
        panic(fmt.Errorf("failed to convert string to public key: %w", err))
    }
    key, ok := ifc.(*rsa.PublicKey)
    if !ok {
        fmt.Errorf("key is not ok")
    }
    return key
}
