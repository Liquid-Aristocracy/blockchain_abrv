package main

import (
	"log"

	"github.com/boltdb/bolt"
)

// BlockchainIterator is used to iterate over blockchain blocks
type DatachainIterator struct {
	currentHash []byte
	db          *bolt.DB
}

// Next returns next block starting from the tip
func (i *DatachainIterator) Next() *DataBlock {
	var block *KeyBlock

	err := i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyBlocksBucket))
		encodedBlock := b.Get(i.currentHash)
		block = DeserializeKeyBlock(encodedBlock)

		return nil
	})

	if err != nil {
		log.Panic(err)
	}

	i.currentHash = block.PrevBlockHash

	return block
}
