package main

import (
	"bytes"
	"encoding/gob"
	"log"
	"time"
)

// Block represents a block in the blockchain
type DataBlock struct {
	Timestamp     int64
	Transactions  []*DataTransaction
	PrevBlockHash []byte
	Hash          []byte
	Sign          []byte
	Author        []byte
	Height        int
}

// NewBlock creates and returns Block
func NewDataBlock(transactions []*DataTransaction, prevBlockHash []byte, height int, privKey ecdsa.PrivateKey, author []byte) *DataBlock {
	block := &DataBlock{time.Now().Unix(), transactions, prevBlockHash, []byte{}, []byte{}, []byte{}, height}
	//pow := NewProofOfWork(block)
	//nonce, hash := pow.Run()
	HashDataBlock(block, privKey)

	block.Hash = hash[:]
	block.Author = author[:]

	return block
}

// NewGenesisBlock creates and returns genesis Block
func NewGenesisDataBlock(privKey ecdsa.PrivateKey, author []byte) *DataBlock {
	return NewBlock([]*DataTransaction{}, []byte{}, 0, privKey, author)
}

// HashTransactions returns a hash of the transactions in the block
func (b *DataBlock) HashTransactions() []byte {
	var transactions [][]byte

	for _, tx := range b.Transactions {
		transactions = append(transactions, tx.Serialize())
	}
	mTree := NewMerkleTree(transactions)

	return mTree.RootNode.Data
}

// Serialize serializes the block
func (b *DataBlock) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	err := encoder.Encode(b)
	if err != nil {
		log.Panic(err)
	}

	return result.Bytes()
}

// DeserializeBlock deserializes a block
func DeserializeDataBlock(d []byte) *DataBlock {
	var block DataBlock

	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}

	return &block
}
