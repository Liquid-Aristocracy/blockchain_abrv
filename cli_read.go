package main

import (
	"fmt"
	"log"
	"crypto/rsa"
)

func (cli *CLI) read(id string) {
    dc := NewDatachain(nodeID)
    kc := NewKeychain(nodeID)
    dtx, err := dc.FindTransaction([]byte(id))
    ktx, err := kc.FindTransaction([]byte(id))
    if err != nil {
	log.Panic(err)
    }
    
    pubByte := DecryptWithABEKey (ktx.Key, abekey, ktx.Policy)
    if pubByte != nil {
	publicKey := RsaByteToPublicKey(pubByte []byte)
	data := RsaPublicDecrypt(publicKey, dtx.Data)
	print(string(data))
    }
}
