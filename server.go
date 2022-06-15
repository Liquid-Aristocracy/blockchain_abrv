package main

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
)

const protocol = "tcp"
const nodeVersion = 1
const commandLength = 12

const taaddr = "localhost:3000"
const mineraddr = "localhost:3001"

var nodeAddress string
var isMiner bool
var myKey ecdsa.PrivateKey
var knownNodes = []string{"localhost:3000"}
var taPubKey []byte
var pubkeys make(map[string][]byte)
var dataBlocksInTransit = [][]byte{}
var keyBlocksInTransit = [][]byte{}
var mempool = make(map[string]Transaction)
var datatranspool = make(map[string]DataTransaction)
var keytranspool = make(map[string]KeyTransaction)
var updatelog = [][]byte{}
var updateloghash = []byte{}

var abekey []byte
var chsk []byte
var chpk []byte
var aaa AbeAuthAsset

type addr struct {
	AddrList []string
}

type datablock struct {
	AddrFrom string
	DataBlock    []byte
}

type keyblock struct {
	AddrFrom string
	KeyBlock    []byte
}

type getdatablocks struct {
	AddrFrom string
}

type getkeyblocks struct {
	AddrFrom string
}

type getdata struct {
	AddrFrom string
	Type     string
	ID       []byte
}

// inventory
type inv struct {
	AddrFrom string
	Type     string
	Items    [][]byte
}

type datatx struct {
	AddFrom     string
	DataTransaction []byte
}

type keytx struct {
	AddFrom     string
	KeyTransaction []byte
}

type datachainverzion struct {
	Version    int
	BestHeight int
	AddrFrom   string
}

type keychainverzion struct {
	Version    int
	BestHeight int
	AddrFrom   string
}

type getidassign struct {
	AddrFrom string
}

type idassign struct {
	AddrFrom  string
	AddrTo    string
	AbeKey    []byte
	ChKey     []byte
	SignKey   ecdsa.PrivateKey
	Attr      []string
	aaa       AbeAuthAsset
}

type attrupdate struct {
	AddrFrom  string
	AddrTo    string
	AbeKey    []byte
	Attr      []string
	Signature []byte
}

type keyassigninfo struct {
	AddrFrom  string
	info      map[string][]byte
	Signature []byte
}

type keychainupdateinfo struct {
	AddrFrom  string
	Attr      string
	NewKey    []byte
	ChSK      []byte
	Signature []byte
}

type keychainupdatefinishing struct {
	AddrFrom  string
}

type keychainupdatelog struct {
	AddrFrom  string
	log       [][]byte
}

type log struct {
	blockheight int
	txid        []byte
	newHash     []byte
}

func (l *log) Serialize() []byte {
    var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(l)
    
    if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

func commandToBytes(command string) []byte {
	var bytes [commandLength]byte

	for i, c := range command {
		bytes[i] = byte(c)
	}

	return bytes[:]
}

func bytesToCommand(bytes []byte) string {
	var command []byte

	for _, b := range bytes {
		if b != 0x0 {
			command = append(command, b)
		}
	}

	return fmt.Sprintf("%s", command)
}

func extractCommand(request []byte) []byte {
	return request[:commandLength]
}

func updateKeychain (newkey []byte, attr string, bc *Keychain) {
	if (isMiner) {
		blocksToOverwrite := bc.FindBlockAndTransactionByAttr(attr)
		newlog := [][]byte{} 
		for block, txidlist := range blocksToOverwrite {
			i := 0
			for j, tx := range block.Transactions {
				if bytes.Compare(tx.ID, txidlist[i]) == 0 {
					data := DecryptWithABEKey(tx.Key, abekey, tx.Policy)
					new_secret := aaa.NewSecret()
					new_kca := EncryptWithABESecret(data, new_secret, tx.Policy)
					new_r := FindCHCollision(tx.Key, new_kca, tx.R, tx.Hash, chpk, chsk)
					block.Transactions[j] := KeyTransaction{tx.ID, tx.Policy, new_kca, new_r, tx.CH, tx.Sign, tx.Auth}
					i = i + 1
					logfortx := log{block.Height, tx.ID, sha256.Sum256(new_kca)}.Serialize()
					newlog = append(newlog, logfortx)
				}
			}
			for _, node := range knownNodes {
				if node != nodeAddress {
					sendInv(node, "keyblock", [][]byte{block.Hash})
					sendKeychainUpdateLog(node, newlog)
				}
			}
			updatelog = append(updatelog, newlog)
			updateloghash = HashUpdateLog(updateloghash, newlog)
		}
		abekey = newkey
	}
}

func requestBlocks() {
	for _, node := range knownNodes {
		sendGetBlocks(node)
	}
}

// send this node's addr list to address
func sendAddr(address string) {
	nodes := addr{knownNodes}
	nodes.AddrList = append(nodes.AddrList, nodeAddress)
	payload := gobEncode(nodes)
	request := append(commandToBytes("addr"), payload...)

	sendData(address, request)
}

// send a block b to address
func sendDataBlock(address string, b *DataBlock) {
	data := datablock{nodeAddress, b.Serialize()}
	payload := gobEncode(data)
	request := append(commandToBytes("datablock"), payload...)

	sendData(address, request)
}

func sendKeyBlock(address string, b *KeyBlock) {
	data := keyblock{nodeAddress, b.Serialize()}
	payload := gobEncode(data)
	request := append(commandToBytes("block"), payload...)

	sendData(address, request)
}

// send data generally
func sendData(address string, data []byte) {
	conn, err := net.Dial(protocol, address)
	if err != nil {
		fmt.Printf("%s is not available\n", address)
		var updatedNodes []string

		for _, node := range knownNodes {
			if node != address {
				updatedNodes = append(updatedNodes, node)
			}
		}

		knownNodes = updatedNodes

		return
	}
	defer conn.Close()

	_, err = io.Copy(conn, bytes.NewReader(data))
	if err != nil {
		log.Panic(err)
	}
}

func sendInv(address, kind string, items [][]byte) {
	inventory := inv{nodeAddress, kind, items}
	payload := gobEncode(inventory)
	request := append(commandToBytes("inv"), payload...)

	sendData(address, request)
}

func sendGetBlocks(address string) {
	sendGetDataBlocks(address)
	sendGetKeyBlocks(address)
}

func sendGetDataBlocks(address string) {
	payload := gobEncode(getdatablocks{nodeAddress})
	request := append(commandToBytes("getdatablocks"), payload...)

	sendData(address, request)
}

func sendGetKeyBlocks(address string) {
	payload := gobEncode(getkeyblocks{nodeAddress})
	request := append(commandToBytes("getkeyblocks"), payload...)

	sendData(address, request)
}

func sendGetData(address, kind string, id []byte) {
	payload := gobEncode(getdata{nodeAddress, kind, id})
	request := append(commandToBytes("getdata"), payload...)

	sendData(address, request)
}

func sendDataTx(address string, tnx *DataTransaction) {
	data := datatx{nodeAddress, tnx.Serialize()}
	payload := gobEncode(data)
	request := append(commandToBytes("datatx"), payload...)

	sendData(address, request)
}

func sendKeyTx(address string, tnx *KeyTransaction) {
	data := keytx{nodeAddress, tnx.Serialize()}
	payload := gobEncode(data)
	request := append(commandToBytes("keytx"), payload...)

	sendData(address, request)
}

func sendVersion(address string, dc *Datachain, kc *Keychain) {
	sendDatachainVersion(address, dc)
	sendKeychainVersion(address, kc)
}

func sendDatachainVersion(address string, bc *Datachain) {
	bestHeight := bc.GetBestHeight()
	payload := gobEncode(datachainverzion{nodeVersion, bestHeight, nodeAddress})

	request := append(commandToBytes("dcversion"), payload...)

	sendData(address, request)
}

func sendKeychainVersion(address string, bc *Keychain) {
	bestHeight := bc.GetBestHeight()
	payload := gobEncode(keychainverzion{nodeVersion, bestHeight, nodeAddress})

	request := append(commandToBytes("kcversion"), payload...)

	sendData(address, request)
}

// new below
func sendGetIDAssign(address string) {
	payload := gobEncode(getidassign{nodeAddress})
	
	request := append(commandToBytes("getidassign"), payload...)
	
	sendData(address, request)
}

func sendIDAssign(address string) {
	var ida idassign
	ida.AddrFrom = nodeAddress
	ida.AddrTo = address
	HandleNewUser(address)
	ida.AbeKey = AssignKey(address, aaa)
	ida.ChKey = chpk
	ida.SignKey, pubkey_new := NewKeyPair()
	ida.Attr = AttrOfUser(address)
	ida.aaa = aaa
	pubkeys[address] = pubkey_new
	payload := gobEncode(ida)
	request := append(commandToBytes("idassign", payload...)
	sendData (address, request)
}

func sendKeyAssignInfo (address string) {
	dataToSign := gobEncode(keyassigninfo{nodeAddress, pubkeys, nil})
	r, s, err := ecdsa.Sign(rand.Reader, &myKey, []byte(dataToSign))
	signature := append(r.Bytes(), s.Bytes()...)
	payload := gobEncode(keyassigninfo{nodeAddress, pubkeys, signature})
	request := append(commandToBytes("keyassigninfo"), payload...)
	sendData(address, request)
}

func sendAttrUpdate (address string) {
	newAbeKey := AssignKey(address, aaa)
	attrs := AttrOfUser(address)
	dataToSign := gobEncode(attrupdate{nodeAddress, address, newAbeKey, attrs, nil})
	r, s, err := ecdsa.Sign(rand.Reader, &myKey, []byte(dataToSign))
	signature := append(r.Bytes(), s.Bytes()...)
	payload := gobEncode(attrupdate{nodeAddress, address, newAbeKey, attrs, signature})
	request := append(commandToBytes("attrupdate"), payload...)
	sendData(address, request)
}

func sendKeychainUpdateInfo (address string, attr string) {
	newAbeKey := AssignKey(address, aaa)
	dataToSign := gobEncode(keychainupdateinfo{nodeAddress, attr, newAbeKey, chsk, nil})
	r, s, err := ecdsa.Sign(rand.Reader, &myKey, []byte(dataToSign))
	signature := append(r.Bytes(), s.Bytes()...)
	payload := gobEncode(keychainupdateinfo{nodeAddress, attr, newAbeKey, chsk, signature})
	request := append(commandToBytes("keychainupdateinfo"), payload...)
	sendData(address, request)
}

func sendKeychainUpdateLog (address string, newlog [][]byte) {
	payload := gobEncode(keychainupdatelog{nodeAddress, newlog})
	
	request := append(commandToBytes("keychainupdatelog"), payload...)
	
	sendData(address, request)
}

func sendFinishKeychainUpdate (address string) {
	payload := gobEncode(keychainupdatefinishing{nodeAddress})
	
	request := append(commandToBytes("keychainupdatefinishing"), payload...)
	
	sendData(address, request)
}

func UpdateAttr (attr string, userResult map[string]bool) {
	var olduser []string
	for user, result := range userResult {
		if result == false {
			olduser = append(olduser, user)
		}
	}
	UpdateAttr(attr, userResult, aaa)
	userlist := UserOfAttr(attr, knownNodes)
	alluser := append(userlist, olduser)
	for user := range allUser {
		if user == mineraddr {
			sendKeychainUpdateInfo(user, attr)
		} else {
			sendAttrUpdate(user)
		}
	}
}

func handleAddr(request []byte) {
	var buff bytes.Buffer
	var payload addr

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	knownNodes = append(knownNodes, payload.AddrList...)
	fmt.Printf("There are %d known nodes now!\n", len(knownNodes))
	requestBlocks()
}

func handleBlock(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload block

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blockData := payload.Block
	block := DeserializeBlock(blockData)

	fmt.Println("Recevied a new block!")
	bc.AddBlock(block)

	fmt.Printf("Added block %x\n", block.Hash)

	if len(blocksInTransit) > 0 {
		blockHash := blocksInTransit[0]
		sendGetData(payload.AddrFrom, "block", blockHash)

		blocksInTransit = blocksInTransit[1:]
	} else {
		UTXOSet := UTXOSet{bc}
		UTXOSet.Reindex()
	}
}

func handleDataBlock(request []byte, bc *Datachain) {
	var buff bytes.Buffer
	var payload datablock

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blockData := payload.DataBlock
	dblock := DeserializeBlock(blockData)

	fmt.Println("Recevied a new datablock!")
	bc.AddBlock(dblock)

	fmt.Printf("Added datablock %x\n", dblock.Hash)
	
	if len(dataBlocksInTransit) > 0 {
		blockHash := dataBlocksInTransit[0]
		sendGetData(payload.AddrFrom, "datablock", blockHash)

		dataBlocksInTransit = dataBlocksInTransit[1:]
	}
}

func handleKeyBlock(request []byte, bc *Keychain) {
	var buff bytes.Buffer
	var payload keyblock

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blockData := payload.KeyBlock
	kblock := DeserializeBlock(blockData)

	fmt.Println("Recevied a new keyblock!")
	bc.AddBlock(kblock)

	fmt.Printf("Added keyblock %x\n", kblock.Hash)
	
	if len(keyBlocksInTransit) > 0 {
		blockHash := keyBlocksInTransit[0]
		sendGetData(payload.AddrFrom, "keyblock", blockHash)

		keyBlocksInTransit = keyBlocksInTransit[1:]
	}
}

func handleInv(request []byte, dc *Datachain, kc *Keychain) {
	var buff bytes.Buffer
	var payload inv

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Recevied inventory with %d %s\n", len(payload.Items), payload.Type)

	if payload.Type == "datablock" {
		//dataBlocksInTransit = payload.Items

		blockHash := payload.Items[0]
		sendGetData(payload.AddrFrom, "datablock", blockHash)

		newInTransit := [][]byte{}
		for _, b := range dataBlocksInTransit {
			if bytes.Compare(b, blockHash) != 0 {
				newInTransit = append(newInTransit, b)
			}
		}
		dataBlocksInTransit = newInTransit
	}
	
	if payload.Type == "keyblock" {
		//keyBlocksInTransit = payload.Items

		blockHash := payload.Items[0]
		sendGetData(payload.AddrFrom, "keyblock", blockHash)

		newInTransit := [][]byte{}
		for _, b := range keyBlocksInTransit {
			if bytes.Compare(b, blockHash) != 0 {
				newInTransit = append(newInTransit, b)
			}
		}
		keyBlocksInTransit = newInTransit
	}

	if payload.Type == "datatx" {
		txID := payload.Items[0]

		if mempool[hex.EncodeToString(txID)].ID == nil {
			sendGetData(payload.AddrFrom, "datatx", txID)
		}
	}
	
	if payload.Type == "keytx" {
		txID := payload.Items[0]

		if mempool[hex.EncodeToString(txID)].ID == nil {
			sendGetData(payload.AddrFrom, "keytx", txID)
		}
	}
}

func handleGetDataBlocks(request []byte, bc *Datachain) {
	var buff bytes.Buffer
	var payload getdatablocks

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blocks := bc.GetBlockHashes()
	sendInv(payload.AddrFrom, "datablock", blocks)
}

func handleGetKeyBlocks(request []byte, bc *Keychain) {
	var buff bytes.Buffer
	var payload getkeyblocks

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	blocks := bc.GetBlockHashes()
	sendInv(payload.AddrFrom, "keyblock", blocks)
}

func handleGetData(request []byte, dc *Datachain, kc *Keychain) {
	var buff bytes.Buffer
	var payload getdata

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	if payload.Type == "datablock" {
		dblock, err := dc.GetBlock([]byte(payload.ID))
		if err != nil {
			return
		}

		sendDataBlock(payload.AddrFrom, &dblock)
	}
	
	if payload.Type == "keyblock" {
		kblock, err := kc.GetBlock([]byte(payload.ID))
		if err != nil {
			return
		}

		sendKeyBlock(payload.AddrFrom, &kblock)
	}

	if payload.Type == "datatx" {
		txID := hex.EncodeToString(payload.ID)
		tx := datatranspool[txID]

		sendDataTx(payload.AddrFrom, &tx)
		// delete(mempool, txID)
	}
	
	if payload.Type == "keytx" {
		txID := hex.EncodeToString(payload.ID)
		tx := keytranspool[txID]

		sendKeyTx(payload.AddrFrom, &tx)
		// delete(mempool, txID)
	}
}

func handleDataTx(request []byte, bc *Datachain) {
	var buff bytes.Buffer
	var payload datatx

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	txData := payload.DataTransaction
	dtx := DeserializeTransaction(txData)
	mempool[hex.EncodeToString(dtx.ID)] = dtx

	if isMiner == false {
		for _, node := range knownNodes {
			if node != nodeAddress && node != payload.AddFrom {
				sendInv(node, "datatx", [][]byte{dtx.ID})
			}
		}
	} else {
		if len(mempool) >= 2 && len(miningAddress) > 0 {
		MineTransactions:
			var txs []*DataTransaction

			for id := range mempool {
				dtx := mempool[id]
				if bc.VerifyTransaction(&dtx, pubkeys) {
					txs = append(txs, &dtx)
				}
			}

			if len(txs) == 0 {
				fmt.Println("All transactions are invalid! Waiting for new ones...")
				return
			}
			newBlock := bc.MineBlock(txs, myKey, [][]byte{nodeAddress})
			fmt.Println("New datablock is mined!")

			for _, dtx := range txs {
				txID := hex.EncodeToString(dtx.ID)
				delete(mempool, txID)
			}

			for _, node := range knownNodes {
				if node != nodeAddress {
					sendInv(node, "datablock", [][]byte{newBlock.Hash})
				}
			}

			if len(mempool) > 0 {
				goto MineTransactions
			}
		}
	}
}

func handleKeyTx(request []byte, bc *Keychain) {
	var buff bytes.Buffer
	var payload keytx

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	txData := payload.KeyTransaction
	ktx := DeserializeTransaction(txData)
	mempool[hex.EncodeToString(ktx.ID)] = ktx

	if isMiner == false {
		for _, node := range knownNodes {
			if node != nodeAddress && node != payload.AddFrom {
				sendInv(node, "datatx", [][]byte{ktx.ID})
			}
		}
	} else {
		if len(mempool) >= 2 && len(miningAddress) > 0 {
		MineTransactions:
			var txs []*KeyTransaction

			for id := range mempool {
				ktx := mempool[id]
				if bc.VerifyTransaction(&ktx, pubkeys) {
					txs = append(txs, &ktx)
				}
			}

			if len(txs) == 0 {
				fmt.Println("All transactions are invalid! Waiting for new ones...")
				return
			}
			newBlock := bc.MineBlock(txs, myKey, [][]byte{nodeAddress}, UpdateLogHash)
			fmt.Println("New keyblock is mined!")

			for _, ktx := range txs {
				txID := hex.EncodeToString(ktx.ID)
				delete(mempool, txID)
			}

			for _, node := range knownNodes {
				if node != nodeAddress {
					sendInv(node, "datablock", [][]byte{newBlock.Hash})
				}
			}

			if len(mempool) > 0 {
				goto MineTransactions
			}
		}
	}
}

func handleVersion(request []byte, bc *Blockchain) {
	var buff bytes.Buffer
	var payload verzion

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	myBestHeight := bc.GetBestHeight()
	foreignerBestHeight := payload.BestHeight

	if myBestHeight < foreignerBestHeight {
		sendGetBlocks(payload.AddrFrom)
	} else if myBestHeight > foreignerBestHeight {
		sendVersion(payload.AddrFrom, bc)
	}

	// sendAddr(payload.AddrFrom)
	if !nodeIsKnown(payload.AddrFrom) {
		knownNodes = append(knownNodes, payload.AddrFrom)
	}
}

func handleGetIdAssign(request []byte) {
	if nodeAddress == taaddr {
		var buff bytes.Buffer
		var payload getidassign

		buff.Write(request[commandLength:])
		dec := gob.NewDecoder(&buff)
		err := dec.Decode(&payload)
		if err != nil {
			log.Panic(err)
		}

		source := payload.AddrFrom
		knownNodes = append(knownNodes, source)
		sendIDAssign(source)
		for _, user := range knownNodes {
			sendKeyAssignInfo(user)
		}
	}
}

func handleIdAssign(request []byte) {
	var buff bytes.Buffer
	var payload idassign

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	if nodeAddress == payload.AddrTo {
		myKey = payload.SignKey
		abekey = payload.AbeKey
		chpk = payload.ChKey
		aaa = payload.aaa
	}
}

func handleAttrUpdate (request []byte) {
	var buff bytes.Buffer
	var payload attrupdate

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	signature := payload.Signature
	payload.Signature = nil
	if VerifySignature(gobEncode(payload), taPubKey) {
		abekey = payload.AbeKey
	}
}

func handleKeychainUpdate (request []byte, bc *Keychain) {
	var buff bytes.Buffer
	var payload keychainupdateinfo

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	signature := payload.Signature
	payload.Signature = nil
	if VerifySignature(gobEncode(payload), taPubKey) {
		chsk = payload.ChSK
		updateKeychain(payload.NewKey, payload.Attr, bc)
		sendFinishKeychainUpdate(payload.AttrFrom)
	}
}

func handleKeychainUpdateLog (request []byte) {
	var buff bytes.Buffer
	var payload keychainupdatelog
	
	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	if payload.AddrFrom == mineraddr {
		updatelog = append(updatelog, payload.log)
		updateloghash = HashUpdateLog(updateloghash, payload.log)
	}
}

func handleKeychainUpdateFinishing (request []byte) {
	var buff bytes.Buffer
	var payload keychainupdatefinishing

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	if payload.AddrFrom == mineraddr {
		fmt.Println("Finished Keychain Update!")
	}
}

// TODO
// handlegetidassign handleidassign handleattrupdate handlekeychainupdate handlekeychainupdatefinishing in handleconnection

func handleConnection(conn net.Conn, dc *Datachain, kc *Keychain) {
	request, err := ioutil.ReadAll(conn)
	if err != nil {
		log.Panic(err)
	}
	command := bytesToCommand(request[:commandLength])
	fmt.Printf("Received %s command\n", command)

	switch command {
	case "addr":
		handleAddr(request)
	case "datablock":
		handleDataBlock(request, dc)
	case "keyblock":
		handleKeyBlock(request, kc)
	case "inv":
		handleInv(request, dc, kc)
	case "getdatablocks":
		handleGetDataBlocks(request, dc)
	case "getkeyblocks":
		handleGetKeyBlocks(request, kc)
	case "getdata":
		handleGetData(request, dc, kc)
	case "datatx":
		handleTx(request, dc)
	case "keytx":
		handleTx(request, kc)
	case "dcversion":
		handleDatachainVersion(request, dc)
	case "dcversion":
		handleKeychainVersion(request, kc)
	case "getidassign":
		handleGetIdAssign(request)
	case "idassign":
		handleIdAssign(request)
	case "attrupdate":
		handleAttrUpdate(request)
	case "keychainupdateinfo":
		handleKeychainUpdate(request, kc)
	case "keychainupdatelog":
		handleKeychainUpdateLog(request)
	case "keychainupdatefinishing":
		handleKeychainUpdateFinishing(request)
	default:
		fmt.Println("Unknown command!")
	}

	conn.Close()
}

// StartServer starts a node
func StartServer(nodeID) {
	nodeAddress = fmt.Sprintf("localhost:%s", nodeID)
	ln, err := net.Listen(protocol, nodeAddress)
	if err != nil {
		log.Panic(err)
	}
	defer ln.Close()
	
	isMiner = false
	if nodeAddress == taaddr {
		aaa = InitABE(nodeAddress)
		chpk, chsk = GenerateCHParameters()
		myKey, taPubKey := NewKeyPair()
	} else {
		sendGetIDAssign(taaddr)
	}
	if nodeAddress == mineraddr {
		isMiner = true
	}

	dc := NewDatachain(nodeID)
	kc := NewKeychain(nodeID)

	if nodeAddress != knownNodes[0] {
		sendVersion(knownNodes[0], dc)
		sendVersion(knownNodes[0], kc)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panic(err)
		}
		go handleConnection(conn, dc, kc)
	}
}

func gobEncode(data interface{}) []byte {
	var buff bytes.Buffer

	enc := gob.NewEncoder(&buff)
	err := enc.Encode(data)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

func nodeIsKnown(address string) bool {
	for _, node := range knownNodes {
		if node == address {
			return true
		}
	}

	return false
}
