package main

import (
	"bytes"
	"crypto/sha256"
    "crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
)

func HashDataBlock(block *DataBlock, privKey ecdsa.PrivateKey) {
	data := bytes.Join(
		[][]byte{
			block.PrevBlockHash,
			block.HashTransactions(),
			IntToHex(block.Timestamp)
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
    
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, hash)
	signature := append(r.Bytes(), s.Bytes()...)

	block.Hash = hash
	block.Sign = signature
}

func HashKeyBlock(block *KeyBlock, privKey ecdsa.PrivateKey) {
	data := bytes.Join(
		[][]byte{
			block.PrevBlockHash,
			block.UpdateLogHash,
			block.HashTransactions(),
			IntToHex(block.Timestamp)
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
    
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, hash)
	signature := append(r.Bytes(), s.Bytes()...)

	block.Hash = hash
	block.Sign = signature
}

func VerifyDataBlock(block *DataBlock, pubkeys map[string][]byte) {
	data := bytes.Join(
		[][]byte{
			block.PrevBlockHash,
			block.HashTransactions(),
			IntToHex(block.Timestamp)
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
	
	if hash != block.Hash {
		return false
	}
    
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, data)
	signature := append(r.Bytes(), s.Bytes()...)

	curve := elliptic.P256()
	pubkey := pubkeys[hex.EncodeToString(block.Author)]

	r := big.Int{}
	s := big.Int{}
	sigLen := len(block.Sign)
	r.SetBytes(block.Sign[:(sigLen / 2)])
	s.SetBytes(block.Sign[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(pubkey)
	x.SetBytes(pubkey[:(keyLen / 2)])
	y.SetBytes(pubkey[(keyLen / 2):])

	rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	if ecdsa.Verify(&rawPubKey, block.Hash, &r, &s) == false {
		return false
	}

	return true
}

func VerifyKeyBlock(block *KeyBlock, pubkeys map[string][]byte) {
	data := bytes.Join(
		[][]byte{
			block.PrevBlockHash,
			block.HashTransactions(),
			IntToHex(block.Timestamp)
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
	
	if hash != block.Hash {
		return false
	}
    
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, data)
	signature := append(r.Bytes(), s.Bytes()...)

	curve := elliptic.P256()
	pubkey := pubkeys[hex.EncodeToString(block.Author)]

	r := big.Int{}
	s := big.Int{}
	sigLen := len(block.Sign)
	r.SetBytes(block.Sign[:(sigLen / 2)])
	s.SetBytes(block.Sign[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(pubkey)
	x.SetBytes(pubkey[:(keyLen / 2)])
	y.SetBytes(pubkey[(keyLen / 2):])

	rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	if ecdsa.Verify(&rawPubKey, block.Hash, &r, &s) == false {
		return false
	}

	return true
}
