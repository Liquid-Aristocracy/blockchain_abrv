package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"

	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
)

const subsidy = 10

// Transaction represents a Bitcoin transaction
type DataTransaction struct {
	ID   []byte
	Data []byte
	Sign []byte
	Auth []byte
}

// Serialize returns a serialized Transaction
func (tx DataTransaction) Serialize() []byte {
	var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

// Hash returns the hash of the Transaction
func (tx *DataTransaction) Hash() []byte {
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = []byte{}

	hash = sha256.Sum256(txCopy.Serialize())

	return hash[:]
}

// TrimmedCopy creates a trimmed copy of Transaction to be used in signing
func (tx *DataTransaction) TrimmedCopy() DataTransaction {

	txCopy := DataTransaction{tx.ID, tx.Data, nil, nil}

	return txCopy
}

// Sign signs each input of a Transaction
func (tx *DataTransaction) Sign(privKey ecdsa.PrivateKey, author []byte) {
	txCopy := tx.TrimmedCopy()
	dataToSign := fmt.Sprintf("%x\n", txCopy)
	
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, []byte(dataToSign))
	signature := append(r.Bytes(), s.Bytes()...)

	tx.Sign = signature
	tx.Auth = author
}

// String returns a human-readable representation of a transaction
func (tx DataTransaction) String() string {
	var lines []string

	lines = append(lines, fmt.Sprintf("--- Data Transaction %x:", tx.ID))
	lines = append(lines, fmt.Sprintf("    Data:      %x", tx.Data))
	lines = append(lines, fmt.Sprintf("    Signature: %x", tx.Sign))
	lines = append(lines, fmt.Sprintf("    Author:    %x", tx.Auth))

	return strings.Join(lines, "\n")
}

// Verify verifies signatures of Transaction inputs
func (tx *DataTransaction) Verify(pubkeys map[string][]byte) bool {
	curve := elliptic.P256()
	pubkey := pubkeys[hex.EncodeToString(tx.Auth)]

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

	txCopy := tx.TrimmedCopy()
	dataToVerify := fmt.Sprintf("%x\n", txCopy)

	rawPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	if ecdsa.Verify(&rawPubKey, []byte(dataToVerify), &r, &s) == false {
		return false
	}
	return true
}

// DeserializeTransaction deserializes a transaction
func DeserializeDataTransaction(data []byte) DataTransaction {
	var transaction DataTransaction

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&transaction)
	if err != nil {
		log.Panic(err)
	}

	return transaction
}
