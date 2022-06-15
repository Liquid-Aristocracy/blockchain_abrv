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

const keyDBFile = "keychain_%s.db"
const keyBlocksBucket = "keyblocks"

// Blockchain implements interactions with a DB
type Keychain struct {
	tip []byte
	db  *bolt.DB
}

// CreateBlockchain creates a new blockchain DB
func CreateKeychain(nodeID string, privKey ecdsa.PrivateKey) *Keychain {
	keyDBFile := fmt.Sprintf(keyDBFile, nodeID)
	if dbExists(keyDBFile) {
		fmt.Println("Keychain already exists.")
		os.Exit(1)
	}

	var tip []byte

	genesis := NewGenesisKeyBlock(privKey, []byte(nodeID))

	db, err := bolt.Open(keyDBFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte(keyBlocksBucket))
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

	bc := Keychain{tip, db}

	return &bc
}

// NewKeyBlockchain creates a new Blockchain with genesis Block
func NewKeychain(nodeID string) *Keychain {
	keyDBFile := fmt.Sprintf(keyDBFile, nodeID)
	if dbExists(keyDBFile) == false {
		fmt.Println("No existing keychain found. Create one first.")
		os.Exit(1)
	}

	var tip []byte
	db, err := bolt.Open(keyDBFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyBlocksBucket))
		tip = b.Get([]byte("l"))

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	bc := Keychain{tip, db}

	return &bc
}

// AddBlock saves the block into the blockchain
func (bc *Keychain) AddBlock(block *KeyBlock) {
	err := bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyBlocksBucket))
		blockInDb := b.Get(block.Hash)

		// handle block overwrite
		//if blockInDb != nil {
		//	return nil
		//}

		blockData := block.Serialize()
		err := b.Put(block.Hash, blockData)
		if err != nil {
			log.Panic(err)
		}

		lastHash := b.Get([]byte("l"))
		lastBlockData := b.Get(lastHash)
		lastBlock := DeserializeKeyBlock(lastBlockData)

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
func (bc *Keychain) FindTransaction(ID []byte) (KeyTransaction, error) {
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

	return KeyTransaction{}, errors.New("Transaction is not found")
}

func (bc *Keychain) FindBlockAndTransactionByAttr(attr string) (*map[KeyBlock][][]byte) {
	bci := bc.Iterator()
	var blist := make(map[KeyBlock][][]byte)

	for {
		block := bci.Next()
		var txidlist := [][]byte
		
		for _, tx := range block.Transactions {
			if IsAttrInPolicy(tx.Policy, attr) {
				txidlist := append(txidlist, tx.id)
			}
		}
		
		if len(txidlist) != 0 {
			blist[block] = txidlist
		}

		if len(block.PrevBlockHash) == 0 {
			break
		}
	}

	return &blist
}

// Iterator returns a BlockchainIterat
func (bc *Keychain) Iterator() *KeychainIterator {
	bci := &BlockchainIterator{bc.tip, bc.db}

	return bci
}

// GetBestHeight returns the height of the latest block
func (bc *Keychain) GetBestHeight() int {
	var lastBlock KeyBlock

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyBlocksBucket))
		lastHash := b.Get([]byte("l"))
		blockData := b.Get(lastHash)
		lastBlock = *DeserializeKeyBlock(blockData)

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	return lastBlock.Height
}

// GetBlock finds a block by its hash and returns it
func (bc *Keychain) GetBlock(blockHash []byte) (KeyBlock, error) {
	var block KeyBlock

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyBlocksBucket))

		blockData := b.Get(blockHash)

		if blockData == nil {
			return errors.New("Block is not found.")
		}

		block = *DeserializeKeyBlock(blockData)

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
func (bc *Keychain) MineBlock(transactions []*KeyTransaction, privKey ecdsa.PrivateKey, author []byte, loghash []byte) *KeyBlock {
	var lastHash []byte
	var lastHeight int

	for _, tx := range transactions {
		// TODO: ignore transaction if it's not valid
		if bc.VerifyTransaction(tx) != true {
			log.Panic("ERROR: Invalid transaction")
		}
	}

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyBlocksBucket))
		lastHash = b.Get([]byte("l"))

		blockData := b.Get(lastHash)
		block := DeserializeKeyBlock(blockData)

		lastHeight = block.Height

		return nil
	})
	if err != nil {
		log.Panic(err)
	}

	newBlock := NewKeyBlock(transactions, lastHash, lastHeight+1, privKey, author, loghash)

	err = bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(keyBlocksBucket))
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
func (bc *Keychain) SignTransaction(tx *KeyTransaction, privKey ecdsa.PrivateKey) {

	tx.Sign(privKey)
}

// VerifyTransaction verifies transaction input signatures
func (bc *Keychain) VerifyTransaction(tx *KeyTransaction, pubkeys map[string][]byte) bool {
	
	return tx.Verify(pubkeys)
}

func dbExists(keyDBFile string) bool {
	if _, err := os.Stat(keyDBFile); os.IsNotExist(err) {
		return false
	}

	return true
}
