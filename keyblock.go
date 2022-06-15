package main

import (
	"bytes"
	"encoding/gob"
	"log"
	"time"
	"errors"
)

// Block represents a block in the blockchain
type KeyBlock struct {
	Timestamp     int64
	Transactions  []*KeyTransaction
	PrevBlockHash []byte
	Hash          []byte
	UpdateLogHash []byte
	Sign          []byte
	Author        []byte
	Height        int
}

// NewBlock creates and returns Block
func NewKeyBlock(transactions []*KeyTransaction, prevBlockHash []byte, height int, privKey ecdsa.PrivateKey, author []byte, loghash []byte) *KeyBlock {
	block := &KeyBlock{time.Now().Unix(), transactions, prevBlockHash, []byte{}, loghash, []byte{}, []byte{}, height}
	//pow := NewProofOfWork(block)
	//nonce, hash := pow.Run()
	HashDataBlock(block, privKey)

	block.Hash = hash[:]
	block.Author = author[:]

	return block
}

// NewGenesisBlock creates and returns genesis Block
func NewGenesisKeyBlock(privKey ecdsa.PrivateKey, author []byte) *KeyBlock {
	return NewBlock([]*KeyTransaction{}, []byte{}, 0, privKey, author, []byte{})
}

// HashTransactions returns a hash of the transactions in the block
func (b *KeyBlock) HashTransactions() []byte {
	var transactions [][]byte

	for _, tx := range b.Transactions {
		txCopy := tx.TrimmedCopy(true)
		transactions = append(transactions, txCopy.Serialize())
	}
	mTree := NewMerkleTree(transactions)

	return mTree.RootNode.Data
}

// Serialize serializes the block
func (b *KeyBlock) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(b)
	if err != nil {
		log.Panic(err)
	}

	return result.Bytes()
}

// DeserializeBlock deserializes a block
func DeserializeKeyBlock(d []byte) *KeyBlock {
	var block KeyBlock

	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}

	return &block
}

func (b *KeyBlock) OverwriteTx (tx KeyTransaction) err {
	for i, btx := range block.Transactions {
		if bytes.Compare(tx.ID, btx.ID) == 0 {
			block.Transactions[i] = tx
			return nil
		}
	}
	return errors.New("Transaction is not found")
}
