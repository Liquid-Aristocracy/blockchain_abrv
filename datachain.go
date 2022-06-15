package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/boltdb/bolt"
)

const dataDBFile = "datachain_%s.db"
const dataBlocksBucket = "datablocks"
const genesisCoinbaseData = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

// Blockchain implements interactions with a DB
type Datachain struct {
	tip []byte
	db  *bolt.DB
}

// CreateBlockchain creates a new blockchain DB
//func CreateDatachain(address, nodeID string) *Datachain {
func CreateDatachain(nodeID string, privKey ecdsa.PrivateKey) *Datachain {
	dataDBFile := fmt.Sprintf(dataDBFile, nodeID)
	if dbExists(dataDBFile) {
		fmt.Println("Datachain already exists.")
		os.Exit(1)
	}

	var tip []byte

	genesis := NewGenesisDataBlock(privKey, []byte(nodeID))

	db, err := bolt.Open(dataDBFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte(dataBlocksBucket))
		if err != nil {
			log.Panic(err)
		}

		err = b.Put(genesis.Hash, genesis.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), genesis.Hash)
		if err != nil {
			log.Panic(err)
		}
		tip = genesis.Hash

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	bc := Datachain{tip, db}

	return &bc
}

// NewDataBlockchain creates a new Blockchain with genesis Block
func NewDatachain(nodeID string) *Datachain {
	dataDBFile := fmt.Sprintf(dataDBFile, nodeID)
	if dbExists(dataDBFile) == false {
		fmt.Println("No existing datachain found. Create one first.")
		os.Exit(1)
	}

	var tip []byte
	db, err := bolt.Open(dataDBFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBlocksBucket))
		tip = b.Get([]byte("l"))

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	bc := Datachain{tip, db}

	return &bc
}

// AddBlock saves the block into the blockchain
func (bc *Datachain) AddBlock(block *DataBlock) {
	err := bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBlocksBucket))
		blockInDb := b.Get(block.Hash)

		if blockInDb != nil {
			return nil
		}

		blockData := block.Serialize()
		err := b.Put(block.Hash, blockData)
		if err != nil {
			log.Panic(err)
		}

		lastHash := b.Get([]byte("l"))
		lastBlockData := b.Get(lastHash)
		lastBlock := DeserializeDataBlock(lastBlockData)

		if block.Height > lastBlock.Height {
			err = b.Put([]byte("l"), block.Hash)
			if err != nil {
				log.Panic(err)
			}
			bc.tip = block.Hash
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}

// FindTransaction finds a transaction by its ID
func (bc *Datachain) FindTransaction(ID []byte) (DataTransaction, error) {
	bci := bc.Iterator()

	for {
		block := bci.Next()

		for _, tx := range block.Transactions {
			if bytes.Compare(tx.ID, ID) == 0 {
				return *tx, nil
			}
		}

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	return DataTransaction{}, errors.New("Transaction is not found")
}

// Iterator returns a BlockchainIterat
func (bc *Datachain) Iterator() *DatachainIterator {
	bci := &BlockchainIterator{bc.tip, bc.db}

	return bci
}

// GetBestHeight returns the height of the latest block
func (bc *Datachain) GetBestHeight() int {
	var lastBlock DataBlock

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBlocksBucket))
		lastHash := b.Get([]byte("l"))
		blockData := b.Get(lastHash)
		lastBlock = *DeserializeDataBlock(blockData)

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return lastBlock.Height
}

// GetBlock finds a block by its hash and returns it
func (bc *Datachain) GetBlock(blockHash []byte) (DataBlock, error) {
	var block DataBlock

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBlocksBucket))

		blockData := b.Get(blockHash)

		if blockData == nil {
			return errors.New("Block is not found.")
		}

		block = *DeserializeDataBlock(blockData)

		return nil
	})
	if err != nil {
		return block, err
	}

	return block, nil
}

// GetBlockHashes returns a list of hashes of all the blocks in the chain
func (bc *Blockchain) GetBlockHashes() [][]byte {
	var blocks [][]byte
	bci := bc.Iterator()

	for {
		block := bci.Next()

		blocks = append(blocks, block.Hash)

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	return blocks
}

// MineBlock mines a new block with the provided transactions
func (bc *Datachain) MineBlock(transactions []*DataTransaction, privKey ecdsa.PrivateKey, author []byte) *DataBlock {
	var lastHash []byte
	var lastHeight int

	for _, tx := range transactions {
		// TODO: ignore transaction if it's not valid
		if bc.VerifyTransaction(tx) != true {
			log.Panic("ERROR: Invalid transaction")
		}
	}

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBlocksBucket))
		lastHash = b.Get([]byte("l"))

		blockData := b.Get(lastHash)
		block := DeserializeDataBlock(blockData)

		lastHeight = block.Height

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	newBlock := NewDataBlock(transactions, lastHash, lastHeight+1, privKey, author)

	err = bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dataBlocksBucket))
		err := b.Put(newBlock.Hash, newBlock.Serialize())
		if err != nil {
			log.Panic(err)
		}

		err = b.Put([]byte("l"), newBlock.Hash)
		if err != nil {
			log.Panic(err)
		}

		bc.tip = newBlock.Hash

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return newBlock
}

// SignTransaction signs inputs of a Transaction
func (bc *Datachain) SignTransaction(tx *DataTransaction, privKey ecdsa.PrivateKey) {

	tx.Sign(privKey)
}

// VerifyTransaction verifies transaction input signatures
func (bc *Datachain) VerifyTransaction(tx *DataTransaction, pubkeys map[string][]byte) bool {
	
	return tx.Verify(pubkeys)
}

func dbExists(dataDBFile string) bool {
	if _, err := os.Stat(dataDBFile); os.IsNotExist(err) {
		return false
	}

	return true
}
